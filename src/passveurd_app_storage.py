import datetime
import json
import os

try:
    import yaml
except Exception:
    yaml = None

from PasswordGenerator import OUTPUT_TYPE_EXTENDED


def serialize_metadata(metadata):
    return {
        "note": metadata.note or "",
        "category": metadata.category or "",
        "last_modified": metadata.last_modified.isoformat()
        if metadata.last_modified
        else None,
    }


def serialize_passveurd(pw):
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
        "iter": int(pw.iter),
        "dk_len": int(pw.dk_len),
        "metadata": serialize_metadata(pw.metadata),
    }


def serialize_cryptopass(pw):
    return {
        "type": "CryptoPass",
        "user_name": pw.user_name,
        "url": pw.url,
        "pass_len": int(pw.pass_len),
        "metadata": serialize_metadata(pw.metadata),
    }


def load_config_from_cookie(cookie_manager, cookie_key):
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


def save_config_to_cookie(cookie_manager, cookie_key, config):
    expires_at = datetime.datetime.now() + datetime.timedelta(days=365)
    cookie_manager.set(cookie_key, json.dumps(config), expires_at=expires_at)


def read_config_from_path(file_path, file_format):
    if not os.path.exists(file_path):
        raise FileNotFoundError("Config file not found.")
    with open(file_path, "r", encoding="utf-8") as handle:
        return _parse_config_text(handle.read(), file_format)


def write_config_to_path(file_path, file_format, config):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    text = dump_config_to_text(config, file_format)
    with open(file_path, "w", encoding="utf-8") as handle:
        handle.write(text)


def read_config_from_upload(file_bytes, file_format):
    text = file_bytes.decode("utf-8")
    return _parse_config_text(text, file_format)


def dump_config_to_text(config, file_format):
    if file_format == "json":
        return json.dumps(config, indent=2)
    if file_format == "yaml":
        if yaml is None:
            raise RuntimeError("PyYAML is not installed.")
        return yaml.safe_dump(config, sort_keys=False)
    raise RuntimeError("Unsupported file format.")


def _parse_config_text(text, file_format):
    if file_format == "json":
        data = json.loads(text)
    elif file_format == "yaml":
        if yaml is None:
            raise RuntimeError("PyYAML is not installed.")
        data = yaml.safe_load(text)
    else:
        raise RuntimeError("Unsupported file format.")
    if not (isinstance(data, dict) and "Passveurd" in data and "CryptoPass" in data):
        raise RuntimeError("File does not look like a Passveurd config.")
    return data


def build_output_type(char_types):
    return OUTPUT_TYPE_EXTENDED(char_types)


def load_app_config(config_path):
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
