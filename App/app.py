"""Streamlit application for Passveurd password generation."""

import os
import sys
from pathlib import Path

# Ensure project root is on path for imports
_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root))
sys.path.insert(0, str(_project_root / "App"))

import streamlit as st
import extra_streamlit_components as stx

from passveurd_app_storage import (
    serialize_passveurd,
    serialize_cryptopass,
    read_config_from_path,
    write_config_to_path,
    read_config_from_upload,
    dump_config_to_text,
    build_output_type,
    load_config_from_cookie,
    save_config_to_cookie,
    load_app_config,
)

from src.PasswordGenerator import (
    Passveurd,
    CryptoPass,
    OUTPUT_TYPE,
    CHARACTER_TYPE,
    PasswordMetaData,
)


def _ensure_defaults(default_state):
    for key, val in default_state.items():
        if key not in st.session_state:
            st.session_state[key] = val


def _get_file_path():
    return os.path.join(
        st.session_state.file_directory,
        f"{st.session_state.file_name}.{st.session_state.file_format}",
    )


def _load_config_from_file():
    file_path = _get_file_path()
    try:
        st.session_state.password_config = read_config_from_path(
            file_path, st.session_state.file_format
        )
        st.success("Config loaded from file.")
    except FileNotFoundError as exc:
        st.warning(str(exc))
    except Exception as exc:
        st.error(f"Could not load file: {exc}")


def _save_config_to_file():
    file_path = _get_file_path()
    try:
        write_config_to_path(
            file_path, st.session_state.file_format, st.session_state.password_config
        )
        st.success("Config saved to file.")
    except Exception as exc:
        st.error(f"Could not save file: {exc}")


def _get_categories(tab_name):
    config = st.session_state.password_config.get(tab_name, {})
    categories = {
        entry.get("metadata", {}).get("category", "")
        for entry in config.values()
        if entry.get("metadata")
    }
    return sorted([cat for cat in categories if cat])


def _get_entries_for_category(tab_name, category):
    config = st.session_state.password_config.get(tab_name, {})
    if category == "(all)":
        return sorted(config.keys())
    entries = []
    for key, entry in config.items():
        if entry.get("metadata", {}).get("category", "") == category:
            entries.append(key)
    return sorted(entries)


def _load_passveurd_into_state(pw):
    st.session_state.pv_service = pw.get("domain", "")
    st.session_state.pv_version = pw.get("version", 0)
    st.session_state.pv_length = pw.get("pass_len", 25)
    st.session_state.pv_offset = pw.get("offset", 0)
    st.session_state.pv_hash_algo = pw.get("hash_name", "sha1")
    st.session_state.pv_iterations = pw.get("iter", 10000)
    st.session_state.pv_dk_len = pw.get("dk_len", 32)
    st.session_state.pv_category = pw.get("metadata", {}).get("category", "")
    st.session_state.pv_note = pw.get("metadata", {}).get("note", "")
    output = pw.get("output_type", {})
    if output.get("kind") == "EXTENDED":
        st.session_state.pv_extended_mode = True
        st.session_state.pv_char_types = output.get("character_types", [])
    else:
        st.session_state.pv_extended_mode = False
        st.session_state.pv_output_type = output.get("name", "ALPHANUMERICPLUS")
    st.session_state.pv_result = ""


def _load_cryptopass_into_state(pw):
    st.session_state.cp_user = pw.get("user_name", "")
    st.session_state.cp_url = pw.get("url", "")
    st.session_state.cp_length = pw.get("pass_len", 25)
    st.session_state.cp_category = pw.get("metadata", {}).get("category", "")
    st.session_state.cp_note = pw.get("metadata", {}).get("note", "")
    st.session_state.cp_result = ""


def _render_saved_passwords(tab_name, on_load, on_delete, key_prefix):
    with st.expander("Saved Passwords", expanded=False):
        categories = _get_categories(tab_name)
        if not categories and not st.session_state.password_config.get(tab_name):
            st.info("No saved entries yet.")
            return
        category = st.selectbox(
            "Category",
            ["(all)"] + categories,
            key=f"{key_prefix}_category_filter",
        )
        entries = _get_entries_for_category(tab_name, category)
        if not entries:
            st.info("No entries for this category.")
            return
        entry_key = st.selectbox(
            "Saved entry",
            entries,
            key=f"{key_prefix}_entry_key",
        )
        col_load, col_delete = st.columns(2)
        if col_load.button("Load Selected", use_container_width=True, key=f"{key_prefix}_load_btn"):
            on_load(entry_key)
        if col_delete.button("Delete Selected", use_container_width=True, key=f"{key_prefix}_delete_btn"):
            on_delete(entry_key)


def main():
    config_path = os.path.join(
        os.path.dirname(__file__), "passveurd_app_config.yaml"
    )
    app_config = load_app_config(config_path)
    st.set_page_config(page_title=app_config["page_title"], layout="centered")
    cookie_manager = stx.CookieManager()

    _ensure_defaults(app_config["default_state"])

    if "cookie_loaded" not in st.session_state:
        cookie_config = load_config_from_cookie(
            cookie_manager, app_config["cookie_key"]
        )
        if cookie_config is not None:
            st.session_state.password_config = cookie_config
        st.session_state.cookie_loaded = True

    with st.sidebar:
        st.text_input("File Directory", key="file_directory")
        with st.expander("Loading", expanded=False):
            st.text_input("File Name", key="file_name")
            st.selectbox("Format", ["json", "yaml"], key="file_format")
            col_load, col_save = st.columns(2)
            if col_load.button("Load", use_container_width=True, key="sidebar_load"):
                _load_config_from_file()
            if col_save.button("Save", use_container_width=True, key="sidebar_save"):
                _save_config_to_file()
            uploaded = st.file_uploader(
                "Import from file",
                type=["json", "yaml"],
                key="config_upload",
            )
            if st.button("Import Upload", use_container_width=True, key="sidebar_import"):
                if uploaded is None:
                    st.warning("Select a file to import.")
                else:
                    try:
                        st.session_state.password_config = read_config_from_upload(
                            uploaded.getvalue(), st.session_state.file_format
                        )
                        save_config_to_cookie(
                            cookie_manager,
                            app_config["cookie_key"],
                            st.session_state.password_config,
                        )
                        st.success("Config imported.")
                    except Exception as exc:
                        st.error(f"Could not import file: {exc}")
            try:
                export_text = dump_config_to_text(
                    st.session_state.password_config, st.session_state.file_format
                )
                st.download_button(
                    "Export Download",
                    data=export_text,
                    file_name=f"{st.session_state.file_name}.{st.session_state.file_format}",
                    use_container_width=True,
                    key="sidebar_export",
                )
            except Exception as exc:
                st.error(str(exc))
            if st.button("Clear Saved Config", use_container_width=True, key="sidebar_clear"):
                st.session_state.password_config = dict(app_config["default_config"])
                save_config_to_cookie(
                    cookie_manager, app_config["cookie_key"], st.session_state.password_config
                )
                st.success("Cleared saved config.")

    tab_passveurd, tab_pin, tab_crypto = st.tabs(
        ["Passveurd", "PIN Config", "CryptoPass"]
    )

    with tab_passveurd:
        _render_saved_passwords(
            "Passveurd",
            on_load=lambda key: _load_passveurd_into_state(
                st.session_state.password_config["Passveurd"][key]
            ),
            on_delete=lambda key: _delete_entry(
                "Passveurd", key, cookie_manager, app_config["cookie_key"]
            ),
            key_prefix="pv_saved",
        )

        st.text_input("Secret", type="password", key="pv_secret")
        st.text_input("Service", key="pv_service")
        st.number_input("Version", min_value=0, max_value=2**32, step=1, key="pv_version")
        st.number_input("Length", min_value=4, max_value=256, step=1, key="pv_length")

        st.checkbox("Extended mode", key="pv_extended_mode")
        if st.session_state.pv_extended_mode:
            st.multiselect(
                "Characters",
                options=[ct.name for ct in CHARACTER_TYPE],
                default=st.session_state.pv_char_types,
                key="pv_char_types",
            )
        else:
            st.selectbox(
                "Type",
                options=["NUMERIC", "ALPHANUMERIC", "ALPHANUMERICPLUS"],
                key="pv_output_type",
            )

        st.text_input("Category", key="pv_category")
        st.text_area("Note", key="pv_note")

        with st.expander("Advanced Options", expanded=False):
            st.number_input("Offset", min_value=0, max_value=1_000_000, step=1, key="pv_offset")
            st.selectbox("Hash Algo", options=["sha1", "sha256"], key="pv_hash_algo")
            st.number_input(
                "Iterations",
                min_value=10_000,
                max_value=1_000_000,
                step=1000,
                key="pv_iterations",
            )
            st.number_input(
                "Key Length",
                min_value=32,
                max_value=256,
                step=1,
                key="pv_dk_len",
            )

        if st.button("Generate", use_container_width=True, key="pv_generate"):
            if st.session_state.pv_extended_mode:
                character_types = [
                    CHARACTER_TYPE[name] for name in st.session_state.pv_char_types
                ]
                output_type = build_output_type(character_types)
                if len(character_types) == 0:
                    st.warning("Select at least one character type.")
                else:
                    pass_generator = Passveurd(
                        st.session_state.pv_service,
                        st.session_state.pv_version,
                        st.session_state.pv_length,
                        output_type,
                        st.session_state.pv_offset,
                        st.session_state.pv_hash_algo,
                        st.session_state.pv_iterations,
                        st.session_state.pv_dk_len,
                        PasswordMetaData(st.session_state.pv_note, st.session_state.pv_category),
                    )
                    st.session_state.pv_result = pass_generator.generate_password(
                        st.session_state.pv_secret
                    )
                    _update_config(pass_generator, cookie_manager, app_config["cookie_key"])
            else:
                output_type = OUTPUT_TYPE[st.session_state.pv_output_type]
                pass_generator = Passveurd(
                    st.session_state.pv_service,
                    st.session_state.pv_version,
                    st.session_state.pv_length,
                    output_type,
                    st.session_state.pv_offset,
                    st.session_state.pv_hash_algo,
                    st.session_state.pv_iterations,
                    st.session_state.pv_dk_len,
                    PasswordMetaData(st.session_state.pv_note, st.session_state.pv_category),
                )
                st.session_state.pv_result = pass_generator.generate_password(
                    st.session_state.pv_secret
                )
                _update_config(pass_generator, cookie_manager, app_config["cookie_key"])

        st.text_area("Generated Password", value=st.session_state.pv_result, height=70, key="pv_result", disabled=True)

    with tab_pin:
        st.text_input("Secret", type="password", key="pin_secret")
        st.text_input("Service", key="pin_service")
        st.number_input("Target PIN", min_value=0, max_value=9999, step=1, key="pin_target_pin")
        st.text_input("Category", key="pin_category")
        st.text_area("Note", key="pin_note")

        with st.expander("Advanced Options", expanded=False):
            st.number_input(
                "Max Offset",
                min_value=0,
                max_value=1_000_000,
                step=1,
                key="pin_max_offset",
            )
            st.selectbox("Hash Algo", options=["sha1", "sha256"], key="pin_hash_algo")
            st.number_input(
                "Iterations",
                min_value=10_000,
                max_value=1_000_000,
                step=1000,
                key="pin_iterations",
            )
            st.number_input(
                "Key Length",
                min_value=32,
                max_value=256,
                step=1,
                key="pin_dk_len",
            )

        if st.button("Generate PIN Config & Copy to Passveurd", use_container_width=True, key="pin_generate"):
            pass_generator = Passveurd(
                st.session_state.pin_service,
                st.session_state.pin_target_pin,
                4,
                build_output_type([CHARACTER_TYPE.NUMERIC]),
                st.session_state.pin_max_offset,
                st.session_state.pin_hash_algo,
                st.session_state.pin_iterations,
                st.session_state.pin_dk_len,
                PasswordMetaData(st.session_state.pin_note, st.session_state.pin_category),
            )
            new_passveurd, _n_found = pass_generator.generate_PIN_config(
                st.session_state.pin_secret,
                f"{st.session_state.pin_target_pin:04d}",
                st.session_state.pin_max_offset,
            )
            st.session_state.pin_result = f"{st.session_state.pin_target_pin:04d}"
            st.session_state.pv_service = new_passveurd.domain
            st.session_state.pv_version = new_passveurd.version
            st.session_state.pv_length = new_passveurd.pass_len
            st.session_state.pv_offset = new_passveurd.offset
            st.session_state.pv_hash_algo = new_passveurd.hash_name
            st.session_state.pv_iterations = new_passveurd.iter
            st.session_state.pv_dk_len = new_passveurd.dk_len
            st.session_state.pv_extended_mode = True
            st.session_state.pv_char_types = [ct.name for ct in new_passveurd.output_type.character_types]
            st.session_state.pv_category = new_passveurd.metadata.category or ""
            st.session_state.pv_note = new_passveurd.metadata.note or ""
            st.session_state.pv_secret = st.session_state.pin_secret
            _update_config(new_passveurd, cookie_manager, app_config["cookie_key"])

        st.text_area("Generated PIN", value=st.session_state.pin_result, height=70, key="pin_result", disabled=True)

    with tab_crypto:
        _render_saved_passwords(
            "CryptoPass",
            on_load=lambda key: _load_cryptopass_into_state(
                st.session_state.password_config["CryptoPass"][key]
            ),
            on_delete=lambda key: _delete_entry(
                "CryptoPass", key, cookie_manager, app_config["cookie_key"]
            ),
            key_prefix="cp_saved",
        )

        st.text_input("Secret", type="password", key="cp_secret")
        st.text_input("UserName", key="cp_user")
        st.text_input("URL", key="cp_url")
        st.number_input("Length", min_value=4, max_value=256, step=1, key="cp_length")
        st.text_input("Category", key="cp_category")
        st.text_area("Note", key="cp_note")

        if st.button("Generate", use_container_width=True, key="cp_generate"):
            pass_generator = CryptoPass(
                st.session_state.cp_user,
                st.session_state.cp_url,
                st.session_state.cp_length,
                PasswordMetaData(st.session_state.cp_note, st.session_state.cp_category),
            )
            st.session_state.cp_result = pass_generator.generate_password(
                st.session_state.cp_secret
            )
            _update_config(pass_generator, cookie_manager, app_config["cookie_key"])

        st.text_area("Generated Password", value=st.session_state.cp_result, height=70, key="cp_result", disabled=True)


def _update_config(pass_generator, cookie_manager, cookie_key):
    if isinstance(pass_generator, Passveurd):
        key = pass_generator.domain
        st.session_state.password_config["Passveurd"][key] = serialize_passveurd(
            pass_generator
        )
    else:
        key = f"{pass_generator.user_name}@{pass_generator.url}"
        st.session_state.password_config["CryptoPass"][key] = serialize_cryptopass(
            pass_generator
        )
    save_config_to_cookie(cookie_manager, cookie_key, st.session_state.password_config)


def _delete_entry(tab_name, key, cookie_manager, cookie_key):
    if key in st.session_state.password_config.get(tab_name, {}):
        del st.session_state.password_config[tab_name][key]
        save_config_to_cookie(cookie_manager, cookie_key, st.session_state.password_config)
        st.success("Entry deleted.")


if __name__ == "__main__":
    main()
