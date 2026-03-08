import json

from pydantic import BaseModel, Field

from pyhardin.config import CONFIG_DIR
from pyhardin.exceptions import StateError

STATE_FILE = CONFIG_DIR / "state.json"


class Finding(BaseModel):
    title: str = ""
    severity: str = "info"
    description: str = ""
    file: str = ""
    current_value: str = ""
    recommended_value: str = ""
    remediation_command: str = ""


class AnalysisResult(BaseModel):
    service_name: str
    findings: str | list[Finding] = Field(default_factory=list)
    summary: str = ""
    remediation_commands: list[str] = Field(default_factory=list)
    status: str = "pending"
    prompt: str = ""
    provider: str = ""
    model: str = ""
    temperature: float = 0.1
    max_tokens: int = 16384
    remediation_applied: bool = False


class ScanState(BaseModel):
    scan_id: str = ""
    scan_date: str = ""
    completed_services: list[str] = Field(default_factory=list)
    results: list[AnalysisResult] = Field(default_factory=list)
    total_services: int = 0
    is_complete: bool = False


def load_all_states() -> list[ScanState]:
    try:
        if not STATE_FILE.exists() or STATE_FILE.stat().st_size == 0:
            return []
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return [ScanState.model_validate(data)]
        return [ScanState.model_validate(item) for item in data]
    except (json.JSONDecodeError, OSError):
        return []


def load_latest_state() -> ScanState | None:
    states = load_all_states()
    return states[-1] if states else None


def save_all_states(states: list[ScanState]) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump([s.model_dump() for s in states], f, indent=2)
    except OSError as e:
        raise StateError(f"Cannot save states: {e}", code="STATE_WRITE_FAIL") from e


def save_state(state: ScanState) -> None:
    states = load_all_states()
    existing_idx = next((i for i, s in enumerate(states) if s.scan_id == state.scan_id), None)
    if existing_idx is not None:
        states[existing_idx] = state
    else:
        states.append(state)
    save_all_states(states)


def delete_state(scan_id: str) -> bool:
    states = load_all_states()
    new_states = [s for s in states if s.scan_id != scan_id]
    if len(new_states) < len(states):
        save_all_states(new_states)
        return True
    return False


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
