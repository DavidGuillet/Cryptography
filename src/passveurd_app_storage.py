"""Serialisation, deserialisation, and persistence helpers for Passveurd configs.

Functions
---------
serialize_metadata      Convert a PasswordMetaData instance to a plain dict.
serialize_passveurd     Convert a Passveurd instance to a plain dict.
serialize_cryptopass    Convert a CryptoPass instance to a plain dict.
load_config_from_cookie Read and validate a config dict from a browser cookie.
save_config_to_cookie   Serialise a config dict and write it to a browser cookie.
read_config_from_path   Load and validate a config from a JSON or YAML file path.
write_config_to_path    Serialise and write a config to a JSON or YAML file path.
read_config_from_upload Parse and validate config bytes uploaded by the user.
dump_config_to_text     Serialise a config dict to a JSON or YAML string.
build_output_type       Construct an OutputTypeExtended from a list of CharacterType.
load_app_config         Load the application-level YAML configuration file.

Constants
---------
SERIALIZERS
    Maps each tab name (``"Passveurd"``, ``"CryptoPass"``) to its serialiser
    function.  Used by the app to avoid isinstance-based dispatch.
"""

import datetime
import json
import os
from typing import Any, Optional

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from PasswordGenerator import OutputTypeExtended


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def serialize_metadata(metadata: Any) -> dict:
    """Convert a :class:`PasswordMetaData` instance to a plain dict.

    Args:
        metadata: A :class:`PasswordMetaData` instance.

    Returns:
        A dict with keys ``note``, ``category``, and ``last_modified``.
    """
    return {
        "note": metadata.note or "",
        "category": metadata.category or "",
        "last_modified": (
            metadata.last_modified.isoformat() if metadata.last_modified else None
        ),
    }


def serialize_passveurd(pw: Any) -> dict:
    """Convert a :class:`Passveurd` instance to a plain dict suitable for storage.

    Args:
        pw: A :class:`Passveurd` instance.

    Returns:
        A dict representation of the password configuration.
    """
    if pw.output_type.is_extended():
        output_type = {
            "kind": "EXTENDED",
            "character_types": [ct.name for ct in pw.output_type.character_types],
        }
    else:
        output_type = {"kind": "STD", "name": pw.output_type.name}
    return {
        "type": "Passveurd",
        "domain": pw.domain,
        "version": int(pw.version),
        "pass_len": int(pw.pass_len),
        "output_type": output_type,
        "offset": int(pw.offset),
        "hash_name": pw.hash_name,
        "iter": int(pw.iterations),
        "dk_len": int(pw.dk_len),
        "metadata": serialize_metadata(pw.metadata),
    }


def serialize_cryptopass(pw: Any) -> dict:
    """Convert a :class:`CryptoPass` instance to a plain dict suitable for storage.

    Args:
        pw: A :class:`CryptoPass` instance.

    Returns:
        A dict representation of the password configuration.
    """
    return {
        "type": "CryptoPass",
        "user_name": pw.user_name,
        "url": pw.url,
        "pass_len": int(pw.pass_len),
        "metadata": serialize_metadata(pw.metadata),
    }


# Maps each tab name to its serialiser function; used for polymorphic dispatch
# in the app (avoids isinstance checks).
SERIALIZERS: dict = {
    "Passveurd": serialize_passveurd,
    "CryptoPass": serialize_cryptopass,
}


# ---------------------------------------------------------------------------
# Cookie persistence
# ---------------------------------------------------------------------------


def load_config_from_cookie(cookie_manager: Any, cookie_key: str) -> Optional[dict]:
    """Read and validate a password config from a browser cookie.

    Args:
        cookie_manager: A ``CookieManager`` instance.
        cookie_key:     The cookie name under which the config is stored.

    Returns:
        The config dict if found and valid, otherwise ``None``.
    """
    raw = cookie_manager.get(cookie_key)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and "Passveurd" in data and "CryptoPass" in data:
            return data
    except Exception:
        return None
    return None


def save_config_to_cookie(
    cookie_manager: Any, cookie_key: str, config: dict
) -> None:
    """Serialise *config* and write it to a browser cookie (1-year expiry).

    Args:
        cookie_manager: A ``CookieManager`` instance.
        cookie_key:     The cookie name to write.
        config:         The password config dict to persist.
    """
    expires_at = datetime.datetime.now() + datetime.timedelta(days=365)
    cookie_manager.set(cookie_key, json.dumps(config), expires_at=expires_at)


# ---------------------------------------------------------------------------
# File-based persistence
# ---------------------------------------------------------------------------


def read_config_from_path(file_path: str, file_format: str) -> dict:
    """Load and validate a config from a JSON or YAML file.

    Args:
        file_path:   Absolute or relative path to the config file.
        file_format: ``"json"`` or ``"yaml"``.

    Returns:
        The validated config dict.

    Raises:
        FileNotFoundError: If *file_path* does not exist.
        RuntimeError:      If the file format is unsupported or the content is invalid.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError("Config file not found.")
    with open(file_path, "r", encoding="utf-8") as handle:
        return _parse_config_text(handle.read(), file_format)


def write_config_to_path(file_path: str, file_format: str, config: dict) -> None:
    """Serialise *config* and write it to *file_path*.

    Creates any missing parent directories automatically.

    Args:
        file_path:   Target file path.
        file_format: ``"json"`` or ``"yaml"``.
        config:      The password config dict to write.

    Raises:
        RuntimeError: If the file format is unsupported.
    """
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    text = dump_config_to_text(config, file_format)
    with open(file_path, "w", encoding="utf-8") as handle:
        handle.write(text)


def read_config_from_upload(file_bytes: bytes, file_format: str) -> dict:
    """Parse and validate config bytes uploaded by the user.

    Args:
        file_bytes:  Raw bytes of the uploaded file (UTF-8 encoded).
        file_format: ``"json"`` or ``"yaml"``.

    Returns:
        The validated config dict.

    Raises:
        RuntimeError: If the format is unsupported or the content is invalid.
    """
    text = file_bytes.decode("utf-8")
    return _parse_config_text(text, file_format)


def dump_config_to_text(config: dict, file_format: str) -> str:
    """Serialise *config* to a JSON or YAML string.

    Args:
        config:      The password config dict to serialise.
        file_format: ``"json"`` or ``"yaml"``.

    Returns:
        The serialised string.

    Raises:
        RuntimeError: If PyYAML is not installed (YAML only) or the format is
            unsupported.
    """
    if file_format == "json":
        return json.dumps(config, indent=2)
    if file_format == "yaml":
        if yaml is None:
            raise RuntimeError("PyYAML is not installed.")
        return yaml.safe_dump(config, sort_keys=False)
    raise RuntimeError(f"Unsupported file format: {file_format!r}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_config_text(text: str, file_format: str) -> dict:
    """Parse *text* as JSON or YAML and validate the expected config structure.

    Args:
        text:        Raw config text.
        file_format: ``"json"`` or ``"yaml"``.

    Returns:
        The validated config dict.

    Raises:
        RuntimeError: If the format is unsupported, PyYAML is missing (YAML), or
            the parsed content does not look like a Passveurd config.
    """
    if file_format == "json":
        data = json.loads(text)
    elif file_format == "yaml":
        if yaml is None:
            raise RuntimeError("PyYAML is not installed.")
        data = yaml.safe_load(text)
    else:
        raise RuntimeError(f"Unsupported file format: {file_format!r}")
    if not (isinstance(data, dict) and "Passveurd" in data and "CryptoPass" in data):
        raise RuntimeError("File does not look like a Passveurd config.")
    return data


# ---------------------------------------------------------------------------
# Utility / factory
# ---------------------------------------------------------------------------


def build_output_type(char_types: list) -> OutputTypeExtended:
    """Construct an :class:`OutputTypeExtended` from a list of :class:`CharacterType`.

    Args:
        char_types: A list of :class:`CharacterType` members.

    Returns:
        A new :class:`OutputTypeExtended` instance.
    """
    return OutputTypeExtended(char_types)


def load_app_config(config_path: str) -> dict:
    """Load the application-level YAML configuration file.

    Args:
        config_path: Path to the YAML app config file.

    Returns:
        A dict with keys ``page_title``, ``cookie_key``, ``default_config``,
        and ``default_state``.

    Raises:
        FileNotFoundError: If *config_path* does not exist.
        RuntimeError:      If PyYAML is not installed.
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError("App config yaml not found.")
    if yaml is None:
        raise RuntimeError("PyYAML is not installed.")
    with open(config_path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    default_config = data.get("default_config") or {"Passveurd": {}, "CryptoPass": {}}
    default_state = data.get("default_state") or {}
    if not default_state.get("password_config"):
        default_state["password_config"] = dict(default_config)
    if not default_state.get("file_directory"):
        default_state["file_directory"] = os.getcwd()
    return {
        "page_title": data.get("page_title", "Passveurd Generator"),
        "cookie_key": data.get("cookie_key", "passveurd_password_config_v1"),
        "default_config": default_config,
        "default_state": default_state,
    }
