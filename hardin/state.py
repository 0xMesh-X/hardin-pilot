import json
from dataclasses import asdict, dataclass, field

from hardin.config import CONFIG_DIR
from hardin.exceptions import StateError

STATE_FILE = CONFIG_DIR / "state.json"


@dataclass
class AnalysisResult:
    service_name: str
    findings: str = ""
    remediation_commands: list[str] = field(default_factory=list)
    status: str = "pending"


@dataclass
class ScanState:
    scan_id: str = ""
    completed_services: list[str] = field(default_factory=list)
    results: list[AnalysisResult] = field(default_factory=list)
    total_services: int = 0
    is_complete: bool = False


def load_state() -> ScanState | None:
    try:
        if not STATE_FILE.exists() or STATE_FILE.stat().st_size == 0:
            return None
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
        state = ScanState(
            scan_id=data.get("scan_id", ""),
            completed_services=data.get("completed_services", []),
            total_services=data.get("total_services", 0),
            is_complete=data.get("is_complete", False),
        )
        for r in data.get("results", []):
            state.results.append(AnalysisResult(
                service_name=r.get("service_name", ""),
                findings=r.get("findings", ""),
                remediation_commands=r.get("remediation_commands", []),
                status=r.get("status", "pending"),
            ))
        return state
    except (json.JSONDecodeError, OSError):
        return None


def save_state(state: ScanState) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "scan_id": state.scan_id,
            "completed_services": state.completed_services,
            "total_services": state.total_services,
            "is_complete": state.is_complete,
            "results": [asdict(r) for r in state.results],
        }
        with open(STATE_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except OSError as e:
        raise StateError(f"Cannot save state: {e}", code="STATE_WRITE_FAIL") from e


def clear_state() -> None:
    try:
        if STATE_FILE.exists():
            STATE_FILE.unlink()
    except OSError:
        pass


def mark_service_complete(state: ScanState, service_name: str, result: AnalysisResult) -> None:
    result.status = "complete"
    state.completed_services.append(service_name)
    existing = [r for r in state.results if r.service_name == service_name]
    if existing:
        idx = state.results.index(existing[0])
        state.results[idx] = result
    else:
        state.results.append(result)
    save_state(state)


def is_service_completed(state: ScanState, service_name: str) -> bool:
    return service_name in state.completed_services
