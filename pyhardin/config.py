import json
from pathlib import Path

from pyhardin.exceptions import ConfigError

CONFIG_DIR = Path.home() / ".pyhardin"

CURRENT_CONTEXT = "cli"


def get_config_file() -> Path:
    filename = "web_config.json" if CURRENT_CONTEXT == "web" else "cli_config.json"
    return CONFIG_DIR / filename


def get_default_config() -> dict:
    return {
        "provider": "gemini" if CURRENT_CONTEXT == "cli" else "",
        "api_key": "",
        "model": "gemini-2.5-flash" if CURRENT_CONTEXT == "cli" else "",
        "api_base": "",  # Optional, for OpenAI-compatible proxies
        "output_dir": str(Path.home() / "pyhardin_reports"),
    }


def ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    cfg = get_config_file()
    cfg.touch(exist_ok=True)
    if cfg.stat().st_size == 0:
        with open(cfg, "w") as f:
            json.dump(get_default_config(), f, indent=2)


def reset_config() -> None:
    cfg = get_config_file()
    if cfg.exists():
        cfg.unlink()
    # Also, delete the state file if it exists, so we start completely fresh
    state_file = CONFIG_DIR / "state.json"
    if state_file.exists():
        state_file.unlink()


def load_config() -> dict:
    ensure_config_dir()
    default_cfg = get_default_config()
    try:
        with open(get_config_file(), "r") as f:
            data = json.load(f)
        merged = {**default_cfg, **data}
        return merged
    except json.JSONDecodeError:
        save_config(default_cfg)
        return default_cfg
    except OSError as e:
        raise ConfigError(f"Cannot read config file: {e}", code="CONFIG_READ_FAIL") from e


def save_config(config: dict) -> None:
    ensure_config_dir()
    try:
        with open(get_config_file(), "w") as f:
            json.dump(config, f, indent=2)
    except OSError as e:
        raise ConfigError(f"Cannot write config file: {e}", code="CONFIG_WRITE_FAIL") from e


def get_api_key() -> str:
    config = load_config()
    return config.get("api_key", "")


def set_api_key(key: str) -> None:
    config = load_config()
    config["api_key"] = key
    save_config(config)


def get_model() -> str:
    config = load_config()
    return config.get("model", get_default_config()["model"])


def set_model(model: str) -> None:
    config = load_config()
    config["model"] = model
    save_config(config)


def get_provider() -> str:
    config = load_config()
    return config.get("provider", get_default_config()["provider"])


def set_provider(provider: str) -> None:
    config = load_config()
    config["provider"] = provider
    save_config(config)


def get_api_base() -> str:
    config = load_config()
    return config.get("api_base", get_default_config()["api_base"])


def set_api_base(api_base: str) -> None:
    config = load_config()
    config["api_base"] = api_base
    save_config(config)


def get_output_dir() -> Path:
    config = load_config()
    return Path(config.get("output_dir", get_default_config()["output_dir"]))
