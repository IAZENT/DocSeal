import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


class AuditLogger:
    """Audit logger for security-critical verification events.

    Logs all verification attempts in append-only, forensic-ready format.
    Each event is timestamped and written as JSON lines.
    """

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path

    def log(self, event: Dict[str, Any]) -> None:
        """Log an audit event with automatic timestamp."""
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
