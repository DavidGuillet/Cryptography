"""Tests for the Streamlit Passveurd app.

Uses Streamlit's AppTest for headless UI testing.
Run with: pytest tests/test_app.py -v
Skip with: pytest -m "not streamlit"
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add project root and App for imports
_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root))
sys.path.insert(0, str(_project_root / "App"))

import pytest

# Mark only the AppTest-based test; logic tests run without Streamlit UI
STREAMLIT_APP_TEST = pytest.mark.streamlit


@pytest.fixture(autouse=True)
def mock_cookie_manager():
    """Patch CookieManager so app runs without browser-dependent components."""
    mock_mod = MagicMock()
    mock_mod.CookieManager.return_value.get.return_value = None
    mock_mod.CookieManager.return_value.set = MagicMock()

    with patch.dict(sys.modules, {"extra_streamlit_components": mock_mod}):
        yield


@STREAMLIT_APP_TEST
def test_app_loads_without_error(mock_cookie_manager):
    """App initializes and runs without raising."""
    from streamlit.testing.v1 import AppTest

    app_path = Path(__file__).resolve().parent.parent / "App" / "app.py"
    at = AppTest.from_file(str(app_path))
    at.run()

    assert at is not None
    assert "Passveurd" in at.session_state["password_config"]
    assert "CryptoPass" in at.session_state["password_config"]
    gen_btn = at.button(key="pv_generate")
    assert gen_btn is not None


def test_app_generation_logic_passveurd():
    """Verify Passveurd generation logic used by the app produces correct output.

    This tests the same flow as the app's Generate button without running AppTest,
    which can be unstable when run repeatedly (Streamlit/plotly interaction).
    """
    from src.PasswordGenerator import (
        Passveurd,
        OUTPUT_TYPE,
        CHARACTER_TYPE,
        PasswordMetaData,
    )

    # Simulate app state: extended mode off, ALPHANUMERICPLUS
    output_type = OUTPUT_TYPE.ALPHANUMERICPLUS
    pg = Passveurd(
        "example.com",
        1,
        16,
        output_type,
        metadata=PasswordMetaData(),
    )
    result = pg.generate_password("test_secret")
    assert len(result) == 16
    assert result.isalnum() or any(c in result for c in "&@!=+-?_")


def test_app_generation_logic_passveurd_extended():
    """Verify extended mode generation logic used by the app."""
    from passveurd_app_storage import build_output_type
    from src.PasswordGenerator import Passveurd, CHARACTER_TYPE, PasswordMetaData

    # Simulate app state: extended mode, LOWER + UPPER + NUMERIC
    char_types = [CHARACTER_TYPE.LOWER, CHARACTER_TYPE.UPPER, CHARACTER_TYPE.NUMERIC]
    output_type = build_output_type(char_types)
    pg = Passveurd("example.com", 1, 12, output_type, metadata=PasswordMetaData())
    result = pg.generate_password("test_secret")

    assert len(result) == 12
    assert any(c.islower() for c in result)
    assert any(c.isupper() for c in result)
    assert any(c.isdigit() for c in result)


def test_app_generation_logic_cryptopass():
    """Verify CryptoPass generation logic used by the app."""
    from src.PasswordGenerator import CryptoPass, PasswordMetaData

    cp = CryptoPass("user", "example.com", 25, PasswordMetaData())
    result = cp.generate_password("test_secret")
    assert len(result) == 25
    assert len(result) > 0


def test_app_widgets_have_unique_keys():
    """Ensure all Streamlit widgets that can be duplicated have explicit key= parameters.

    Streamlit auto-generates IDs from widget type + label. Multiple widgets with the same
    type and label (e.g. text_area 'Generated Password' in multiple tabs) cause
    StreamlitDuplicateElementId. This static check catches missing keys before runtime.

    Why AppTest may not catch it: AppTest can use a different Streamlit version or
    execution path than the live app; duplicate-ID enforcement may vary by version.
    """
    app_path = Path(__file__).resolve().parent.parent / "App" / "app.py"
    source = app_path.read_text(encoding="utf-8")

    # Widgets that require unique keys when used multiple times
    # Pattern: st.widget_name(...) - we need key= in the call
    import re

    widget_patterns = [
        (r"st\.(text_area)\s*\(", "text_area"),
        (r"st\.(button)\s*\(", "button"),
        (r"st\.(download_button)\s*\(", "download_button"),
    ]

    # Find all widget calls and their character positions
    for pattern, widget_type in widget_patterns:
        for match in re.finditer(pattern, source):
            start = match.end()
            # Find the matching closing paren for this call (simplified: assume no nested parens in first 500 chars)
            depth = 1
            pos = start
            end = min(start + 800, len(source))
            while pos < end and depth > 0:
                if source[pos] == "(":
                    depth += 1
                elif source[pos] == ")":
                    depth -= 1
                pos += 1
            call_text = source[start : pos - 1]
            if "key=" not in call_text:
                raise AssertionError(
                    f"{widget_type} at line ~{source[:match.start()].count(chr(10)) + 1} "
                    f"missing key= parameter. Add key='unique_id' to avoid StreamlitDuplicateElementId."
                )


def test_app_storage_serialize_roundtrip():
    """Storage serialize/deserialize preserves config structure."""
    from passveurd_app_storage import (
        serialize_passveurd,
        serialize_cryptopass,
        dump_config_to_text,
        _parse_config_text,
    )
    from src.PasswordGenerator import Passveurd, CryptoPass, OUTPUT_TYPE, PasswordMetaData

    pw = Passveurd("x.com", 1, 10, OUTPUT_TYPE.ALPHANUMERICPLUS, metadata=PasswordMetaData())
    cp = CryptoPass("u", "url.com", 20, PasswordMetaData())

    config = {
        "Passveurd": {"x.com": serialize_passveurd(pw)},
        "CryptoPass": {"u@url.com": serialize_cryptopass(cp)},
    }

    # Roundtrip via JSON
    text = dump_config_to_text(config, "json")
    parsed = _parse_config_text(text, "json")
    assert parsed["Passveurd"]["x.com"]["domain"] == "x.com"
    assert parsed["CryptoPass"]["u@url.com"]["user_name"] == "u"
