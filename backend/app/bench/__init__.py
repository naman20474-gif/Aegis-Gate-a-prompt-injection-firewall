"""Deterministic Aegis Gate benchmark."""
from .cases import BENCHMARK_CASES, BenchmarkCase


def run_benchmark(*args, **kwargs):
    # Lazy import keeps ``python -m backend.app.bench.runner`` warning-free.
    from .runner import run_benchmark as _run_benchmark
    return _run_benchmark(*args, **kwargs)


__all__ = ["BENCHMARK_CASES", "BenchmarkCase", "run_benchmark"]
