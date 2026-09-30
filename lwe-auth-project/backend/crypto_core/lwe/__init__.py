from importlib import import_module
from typing import Any

__all__ = [
    "LWEParameters",
    "generate_binary_lwe_keypair",
    "generate_standard_lwe_keypair",
]


def __getattr__(name: str) -> Any:
    # The Sage-based keygen helpers are imported lazily: loading sage.all is slow
    # and would otherwise run inside every process that imports the NumPy-based
    # primitives of this package (API, benchmark harness, other protocols).
    if name in __all__:
        return getattr(import_module("crypto_core.lwe.keygen"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
