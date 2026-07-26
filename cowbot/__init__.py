"""Graph-informed replayable watchdog primitives."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from .contracts import (
        Edge,
        Metric,
        Sample,
        StreamSchema,
        ValidationError,
    )
    from .monitor import MonitorConfig, MonitorReport, monitor_stream
    from .report import (
        PreparedReport,
        prepare_report,
        prepare_report_path,
        publish_report_path,
    )

__all__ = [
    "Edge",
    "Metric",
    "MonitorConfig",
    "MonitorReport",
    "PreparedReport",
    "Sample",
    "StreamSchema",
    "ValidationError",
    "monitor_stream",
    "prepare_report",
    "prepare_report_path",
    "publish_report_path",
]

_LAZY_EXPORTS: Final = {
    "Edge": ("contracts", "Edge"),
    "Metric": ("contracts", "Metric"),
    "MonitorConfig": ("monitor", "MonitorConfig"),
    "MonitorReport": ("monitor", "MonitorReport"),
    "PreparedReport": ("report", "PreparedReport"),
    "Sample": ("contracts", "Sample"),
    "StreamSchema": ("contracts", "StreamSchema"),
    "ValidationError": ("contracts", "ValidationError"),
    "monitor_stream": ("monitor", "monitor_stream"),
    "prepare_report": ("report", "prepare_report"),
    "prepare_report_path": ("report", "prepare_report_path"),
    "publish_report_path": ("report", "publish_report_path"),
}


def __getattr__(name: str) -> object:
    """Resolve the stable public API without importing heavy runtime modules."""

    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(f".{module_name}", __name__), attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()).union(__all__))


__version__ = "0.1.0"
