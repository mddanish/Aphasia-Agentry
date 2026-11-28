"""Detection correlation: match a run's evidence against Wazuh alerts, build the TUI view."""
from aphasia.detect.wazuh import detect

__all__ = ["detect"]
