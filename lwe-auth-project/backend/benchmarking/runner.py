from __future__ import annotations

import hashlib
import json
import os
import random
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from benchmarking.code_metrics import collect_implementation_metrics
from benchmarking.config import BenchmarkConfig
from benchmarking.conformance import run_conformance_checks
from benchmarking.environment import collect_environment
from benchmarking.memory import observe_memory
from benchmarking.network import projected_transport_time_ms
from benchmarking.serialization import (
    canonical_json_bytes,
    serialized_size_bytes,
    wire_message_bytes,
)
from benchmarking.statistics import summarize_measurements
from benchmarking.types import ExperimentResult, Measurement, ProtocolRunResult
from crypto_core.interface import AuthProtocol
from crypto_core.registry import ProtocolSpec, get_protocol_spec


class BenchmarkExecutionError(RuntimeError):
    pass


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _time_call(operation: Callable[[], Any]) -> tuple[Any, float, float]:
    cpu_start = time.process_time_ns()
    wall_start = time.perf_counter_ns()
    result = operation()
    wall_ns = time.perf_counter_ns() - wall_start
    cpu_ns = time.process_time_ns() - cpu_start
    return result, wall_ns / 1_000_000.0, cpu_ns / 1_000_000.0


def _timing_measurements(
    operation: str,
    iteration: int,
    wall_ms: float,
    cpu_ms: float,
    category: str = "timing",
) -> list[Measurement]:
    return [
        Measurement(category, operation, "wall_time", wall_ms, "ms", iteration),
        Measurement(category, operation, "cpu_time", cpu_ms, "ms", iteration),
    ]


class BenchmarkRunner:
    def __init__(self, config: BenchmarkConfig) -> None:
        self.config = config

    def run_protocol(self, spec: ProtocolSpec) -> ProtocolRunResult:
        protocol = spec.require_implementation()
        parameters = protocol.resolve_parameters(
            self.config.protocol_parameters.get(spec.protocol_id, {})
        )
        checks = run_conformance_checks(protocol, parameters)
        run_id = str(uuid.uuid4())
        measurements: list[Measurement] = []
        measurements.extend(collect_implementation_metrics(protocol, spec, parameters))

        self._warm_up(protocol, parameters)
        measurements.extend(self._run_timing(protocol, spec, parameters))
        measurements.extend(self._run_memory(protocol, parameters))
        measurements.extend(self._derive_network_metrics(spec, measurements))

        summaries = summarize_measurements(measurements)
        return ProtocolRunResult(
            run_id=run_id,
            protocol_name=spec.protocol_id,
            display_name=spec.display_name,
            parameters=parameters,
            measurements=measurements,
            summaries=summaries,
            conformance_checks=checks,
        )

    def run_experiment(self, protocol_ids: list[str]) -> ExperimentResult:
        if not protocol_ids:
            raise BenchmarkExecutionError("Debe seleccionarse al menos un protocolo.")

        canonical_ids = [get_protocol_spec(name).protocol_id for name in protocol_ids]
        if len(canonical_ids) != len(set(canonical_ids)):
            raise BenchmarkExecutionError(
                "Un protocolo no puede aparecer más de una vez en el mismo experimento."
            )

        protocol_order = list(canonical_ids)
        if self.config.randomize_protocol_order and len(protocol_order) > 1:
            random.Random(self.config.protocol_order_seed).shuffle(protocol_order)

        config_dict = self.config.model_dump(mode="json")
        config_sha256 = hashlib.sha256(canonical_json_bytes(config_dict)).hexdigest()
        git_commit = os.getenv("BENCHMARK_GIT_COMMIT", "unknown")
        git_dirty = os.getenv("BENCHMARK_GIT_DIRTY", "false").lower() == "true"
        environment = collect_environment()
        environment["benchmark"] = {
            "timer_wall": "time.perf_counter_ns",
            "timer_cpu": "time.process_time_ns",
            "protocol_order_seed": self.config.protocol_order_seed,
            "protocol_order_randomized": self.config.randomize_protocol_order,
        }

        experiment_id = str(uuid.uuid4())
        started_at = _utc_now_iso()
        runs: list[ProtocolRunResult] = []
        for index, protocol_id in enumerate(protocol_order):
            if index and self.config.cooldown_seconds_between_protocols > 0:
                time.sleep(self.config.cooldown_seconds_between_protocols)
            runs.append(self.run_protocol(get_protocol_spec(protocol_id)))
        finished_at = _utc_now_iso()

        return ExperimentResult(
            experiment_id=experiment_id,
            experiment_name=self.config.experiment_name,
            config=config_dict,
            config_sha256=config_sha256,
            environment=environment,
            git_commit=git_commit,
            git_dirty=git_dirty,
            protocol_order=protocol_order,
            started_at_utc=started_at,
            finished_at_utc=finished_at,
            protocol_runs=runs,
        )

    def _warm_up(self, protocol: AuthProtocol, parameters: dict[str, Any]) -> None:
        system_parameters = protocol.generate_system_parameters(**parameters)
        for _ in range(self.config.warmup_iterations):
            public_key, private_key = protocol.generate_keypair(
                system_parameters,
                **parameters,
            )
            challenge = protocol.generate_challenge(system_parameters, public_key)
            response = protocol.solve_challenge(
                system_parameters,
                private_key,
                challenge,
            )
            if not protocol.verify_response(
                system_parameters,
                public_key,
                challenge,
                response,
            ):
                raise BenchmarkExecutionError(
                    f"El warm-up de '{protocol.name}' produjo una autenticación inválida."
                )

    def _run_timing(
        self,
        protocol: AuthProtocol,
        spec: ProtocolSpec,
        parameters: dict[str, Any],
    ) -> list[Measurement]:
        measurements: list[Measurement] = []

        representative_system: dict[str, Any] | None = None
        for iteration in range(self.config.timing_iterations):
            system_parameters, wall_ms, cpu_ms = _time_call(
                lambda: protocol.generate_system_parameters(**parameters)
            )
            canonical_json_bytes(system_parameters)
            measurements.extend(_timing_measurements("setup", iteration, wall_ms, cpu_ms))
            measurements.extend(
                self._setup_size_measurements(iteration, spec.protocol_id, system_parameters)
            )
            if representative_system is None:
                representative_system = system_parameters

        assert representative_system is not None

        representative_public: dict[str, Any] | None = None
        representative_private: dict[str, Any] | None = None
        for iteration in range(self.config.timing_iterations):
            (public_key, private_key), wall_ms, cpu_ms = _time_call(
                lambda: protocol.generate_keypair(representative_system, **parameters)
            )
            measurements.extend(_timing_measurements("keygen", iteration, wall_ms, cpu_ms))
            measurements.extend(
                self._artifact_size_measurements(
                    spec.protocol_id,
                    iteration,
                    public_key,
                    private_key,
                )
            )
            if representative_public is None:
                representative_public = public_key
                representative_private = private_key

        assert representative_public is not None and representative_private is not None

        # Authentication timing intentionally cycles through several pre-generated
        # identities. Key generation is kept outside the authentication timer while
        # avoiding measurements that depend on one unusually cache-friendly key only.
        authentication_key_sets = [
            protocol.generate_keypair(representative_system, **parameters)
            for _ in range(self.config.authentication_key_sets)
        ]
        authentication_wall_samples: list[float] = []

        for iteration in range(self.config.timing_iterations):
            public_key, private_key = authentication_key_sets[
                iteration % len(authentication_key_sets)
            ]
            challenge, challenge_wall, challenge_cpu = _time_call(
                lambda: protocol.generate_challenge(
                    representative_system,
                    public_key,
                )
            )
            response, response_wall, response_cpu = _time_call(
                lambda: protocol.solve_challenge(
                    representative_system,
                    private_key,
                    challenge,
                )
            )
            is_valid, verify_wall, verify_cpu = _time_call(
                lambda: protocol.verify_response(
                    representative_system,
                    public_key,
                    challenge,
                    response,
                )
            )
            if not is_valid:
                raise BenchmarkExecutionError(
                    f"'{spec.protocol_id}' produjo una autenticación inválida durante medición."
                )

            _, auth_wall, auth_cpu = _time_call(
                lambda: self._full_authentication(
                    protocol,
                    representative_system,
                    public_key,
                    private_key,
                )
            )

            measurements.extend(
                _timing_measurements("challenge", iteration, challenge_wall, challenge_cpu)
            )
            measurements.extend(
                _timing_measurements("response", iteration, response_wall, response_cpu)
            )
            measurements.extend(
                _timing_measurements("verify", iteration, verify_wall, verify_cpu)
            )
            measurements.extend(
                _timing_measurements("authentication", iteration, auth_wall, auth_cpu)
            )
            authentication_wall_samples.append(auth_wall)
            measurements.extend(
                self._communication_measurements(
                    spec.protocol_id,
                    iteration,
                    challenge,
                    response,
                )
            )
            measurements.extend(
                self._serialization_measurements(iteration, challenge, response)
            )

        total_auth_ms = sum(authentication_wall_samples)
        measurements.append(
            Measurement(
                "throughput",
                "authentication",
                "sequential_rate",
                (1000.0 * len(authentication_wall_samples) / total_auth_ms)
                if total_auth_ms > 0
                else 0.0,
                "auth/s",
                None,
                {
                    "calculation": "N / sum(authentication_wall_time)",
                    "sample_count": len(authentication_wall_samples),
                },
            )
        )

        return measurements

    def _run_memory(
        self,
        protocol: AuthProtocol,
        parameters: dict[str, Any],
    ) -> list[Measurement]:
        measurements: list[Measurement] = []
        if self.config.memory_iterations == 0:
            return measurements

        system_parameters = protocol.generate_system_parameters(**parameters)
        public_key, private_key = protocol.generate_keypair(system_parameters, **parameters)
        challenge = protocol.generate_challenge(system_parameters, public_key)

        def fresh_verification() -> Callable[[], Any]:
            # A verifier may keep single-use state (for example a spent-ticket log).
            # Every measured verification gets its own challenge and response, built
            # outside the measured region, so repetitions never measure the rejection
            # of a replay instead of a verification.
            fresh_challenge = protocol.generate_challenge(system_parameters, public_key)
            fresh_response = protocol.solve_challenge(
                system_parameters,
                private_key,
                fresh_challenge,
            )

            def verify() -> None:
                if not protocol.verify_response(
                    system_parameters,
                    public_key,
                    fresh_challenge,
                    fresh_response,
                ):
                    raise BenchmarkExecutionError(
                        f"'{protocol.name}' rechazó una respuesta válida durante la "
                        "medición de memoria."
                    )

            return verify

        operations: dict[str, Callable[[], Any]] = {
            "setup": lambda: protocol.generate_system_parameters(**parameters),
            "keygen": lambda: protocol.generate_keypair(system_parameters, **parameters),
            "challenge": lambda: protocol.generate_challenge(system_parameters, public_key),
            "response": lambda: protocol.solve_challenge(
                system_parameters,
                private_key,
                challenge,
            ),
            "authentication": lambda: self._full_authentication(
                protocol,
                system_parameters,
                public_key,
                private_key,
            ),
        }
        measured_order = ("setup", "keygen", "challenge", "response", "verify", "authentication")

        for operation_name in measured_order:
            for iteration in range(self.config.memory_iterations):
                operation = (
                    fresh_verification()
                    if operation_name == "verify"
                    else operations[operation_name]
                )
                _, observation = observe_memory(
                    operation,
                    self.config.memory_sample_interval_ms,
                )
                measurements.extend(
                    [
                        Measurement(
                            "memory",
                            operation_name,
                            "mean_rss_delta",
                            float(observation.mean_rss_delta_bytes),
                            "bytes",
                            iteration,
                        ),
                        Measurement(
                            "memory",
                            operation_name,
                            "peak_rss_delta",
                            float(observation.peak_rss_delta_bytes),
                            "bytes",
                            iteration,
                        ),
                        Measurement(
                            "memory",
                            operation_name,
                            "peak_python_alloc",
                            float(observation.peak_python_alloc_bytes),
                            "bytes",
                            iteration,
                        ),
                    ]
                )

        return measurements

    @staticmethod
    def _full_authentication(
        protocol: AuthProtocol,
        system_parameters: dict[str, Any],
        public_key: dict[str, Any],
        private_key: dict[str, Any],
    ) -> bool:
        challenge = protocol.generate_challenge(system_parameters, public_key)
        response = protocol.solve_challenge(
            system_parameters,
            private_key,
            challenge,
        )
        valid = protocol.verify_response(
            system_parameters,
            public_key,
            challenge,
            response,
        )
        if not valid:
            raise BenchmarkExecutionError("La autenticación completa falló.")
        return True

    @staticmethod
    def _setup_size_measurements(
        iteration: int,
        protocol_name: str,
        system_parameters: dict[str, Any],
    ) -> list[Measurement]:
        has_generated_setup = bool(system_parameters)
        size = serialized_size_bytes(system_parameters) if has_generated_setup else 0
        distribution_wire = (
            len(wire_message_bytes("system_parameters", protocol_name, system_parameters))
            if has_generated_setup
            else 0
        )
        return [
            Measurement(
                "artifact_size",
                "setup",
                "system_parameters",
                float(size),
                "bytes",
                iteration,
                {"persistence": "shared", "sensitive": False, "present": has_generated_setup},
            ),
            Measurement(
                "storage",
                "shared_deployment",
                "system_parameters",
                float(size),
                "bytes",
                iteration,
            ),
            Measurement(
                "communication",
                "setup",
                "system_parameters_distribution",
                float(distribution_wire),
                "bytes",
                iteration,
                {
                    "amortization": "one-time/shared; do not add to every authentication",
                    "present": has_generated_setup,
                },
            ),
        ]

    @staticmethod
    def _artifact_size_measurements(
        protocol_name: str,
        iteration: int,
        public_key: dict[str, Any],
        private_key: dict[str, Any],
    ) -> list[Measurement]:
        public_size = serialized_size_bytes(public_key)
        private_size = serialized_size_bytes(private_key)
        public_registration_wire = len(
            wire_message_bytes("public_key_registration", protocol_name, public_key)
        )
        return [
            Measurement(
                "artifact_size",
                "enrollment",
                "public_key",
                float(public_size),
                "bytes",
                iteration,
                {"persistence": "server", "sensitive": False},
            ),
            Measurement(
                "artifact_size",
                "enrollment",
                "private_key",
                float(private_size),
                "bytes",
                iteration,
                {"persistence": "client", "sensitive": True},
            ),
            Measurement(
                "storage",
                "per_user",
                "server_persistent",
                float(public_size),
                "bytes",
                iteration,
            ),
            Measurement(
                "storage",
                "per_user",
                "client_persistent",
                float(private_size),
                "bytes",
                iteration,
            ),
            Measurement(
                "storage",
                "per_user",
                "combined_persistent",
                float(public_size + private_size),
                "bytes",
                iteration,
            ),
            Measurement(
                "communication",
                "enrollment",
                "public_key_registration",
                float(public_registration_wire),
                "bytes",
                iteration,
                {"amortization": "one-time/per-user"},
            ),
        ]

    @staticmethod
    def _communication_measurements(
        protocol_name: str,
        iteration: int,
        challenge: dict[str, Any],
        response: dict[str, Any],
    ) -> list[Measurement]:
        challenge_payload = serialized_size_bytes(challenge)
        response_payload = serialized_size_bytes(response)
        challenge_wire = len(wire_message_bytes("challenge", protocol_name, challenge))
        response_wire = len(wire_message_bytes("response", protocol_name, response))
        total_wire = challenge_wire + response_wire

        return [
            Measurement(
                "artifact_size",
                "authentication",
                "challenge",
                float(challenge_payload),
                "bytes",
                iteration,
            ),
            Measurement(
                "artifact_size",
                "authentication",
                "response",
                float(response_payload),
                "bytes",
                iteration,
            ),
            Measurement(
                "communication",
                "authentication",
                "challenge_message",
                float(challenge_wire),
                "bytes",
                iteration,
            ),
            Measurement(
                "communication",
                "authentication",
                "response_message",
                float(response_wire),
                "bytes",
                iteration,
            ),
            Measurement(
                "communication",
                "authentication",
                "total_application_payload",
                float(total_wire),
                "bytes",
                iteration,
                {
                    "scope": "canonical cryptographic application envelope",
                    "excludes": ["HTTP", "TLS", "TCP/IP", "retransmissions"],
                },
            ),
            Measurement(
                "communication",
                "authentication",
                "message_count",
                2.0,
                "count",
                iteration,
            ),
            Measurement(
                "communication",
                "authentication",
                "round_trips",
                1.0,
                "count",
                iteration,
            ),
        ]

    @staticmethod
    def _serialization_measurements(
        iteration: int,
        challenge: dict[str, Any],
        response: dict[str, Any],
    ) -> list[Measurement]:
        measurements: list[Measurement] = []
        for name, value in (("challenge", challenge), ("response", response)):
            encoded, encode_wall, encode_cpu = _time_call(
                lambda value=value: canonical_json_bytes(value)
            )
            _, decode_wall, decode_cpu = _time_call(
                lambda encoded=encoded: json.loads(encoded.decode("utf-8"))
            )
            measurements.extend(
                _timing_measurements(
                    f"serialize_{name}",
                    iteration,
                    encode_wall,
                    encode_cpu,
                    category="serialization",
                )
            )
            measurements.extend(
                _timing_measurements(
                    f"deserialize_{name}",
                    iteration,
                    decode_wall,
                    decode_cpu,
                    category="serialization",
                )
            )
        return measurements

    def _derive_network_metrics(
        self,
        spec: ProtocolSpec,
        measurements: list[Measurement],
    ) -> list[Measurement]:
        payloads = [
            item.value
            for item in measurements
            if item.category == "communication"
            and item.operation == "authentication"
            and item.metric_name == "total_application_payload"
        ]
        auth_wall = [
            item.value
            for item in measurements
            if item.category == "timing"
            and item.operation == "authentication"
            and item.metric_name == "wall_time"
        ]
        serialization_wall = [
            item.value
            for item in measurements
            if item.category == "serialization" and item.metric_name == "wall_time"
        ]
        if not payloads or not auth_wall:
            return []

        mean_payload = sum(payloads) / len(payloads)
        mean_auth = sum(auth_wall) / len(auth_wall)
        mean_serialization = (
            sum(serialization_wall) / self.config.timing_iterations
            if serialization_wall
            else 0.0
        )

        derived: list[Measurement] = []
        for scenario in self.config.network_scenarios:
            transport_ms = projected_transport_time_ms(
                round(mean_payload),
                scenario,
                round_trips=1.0,
            )
            metadata = {
                "scenario": scenario.name,
                "rtt_ms": scenario.rtt_ms,
                "bandwidth_mbps": scenario.bandwidth_mbps,
                "description": scenario.description,
                "protocol": spec.protocol_id,
                "model_scope": "projection, not packet-level emulation",
            }
            derived.extend(
                [
                    Measurement(
                        "network_projection",
                        "authentication",
                        "transport_time",
                        transport_ms,
                        "ms",
                        None,
                        metadata,
                    ),
                    Measurement(
                        "network_projection",
                        "authentication",
                        "projected_e2e_time",
                        mean_auth + mean_serialization + transport_ms,
                        "ms",
                        None,
                        metadata,
                    ),
                ]
            )
        return derived
