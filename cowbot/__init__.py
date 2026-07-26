"""Graph-informed replayable watchdog primitives."""

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

__version__ = "0.1.0"
