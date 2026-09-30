from __future__ import annotations

from benchmarking.config import NetworkScenario


def projected_transport_time_ms(
    payload_bytes: int,
    scenario: NetworkScenario,
    round_trips: float = 1.0,
) -> float:
    """Project transport delay from application payload, RTT and bandwidth.

    This intentionally excludes TCP/TLS/HTTP headers, connection setup, congestion,
    retransmissions and server queueing. It is a deterministic comparison model, not
    a substitute for a real network benchmark.
    """
    serialization_time_ms = (
        payload_bytes * 8.0 / (scenario.bandwidth_mbps * 1_000_000.0) * 1000.0
    )
    return round_trips * scenario.rtt_ms + serialization_time_ms
