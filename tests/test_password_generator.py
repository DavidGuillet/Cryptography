"""Tests for PasswordGenerator, Passveurd, and CryptoPass."""

import sys
from pathlib import Path

# Add project root for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
import yaml
from src.PasswordGenerator import (
    Passveurd,
    CryptoPass,
    CHARACTER_TYPE,
    OUTPUT_TYPE,
    OUTPUT_TYPE_EXTENDED,
    PasswordMetaData,
)


def _load_test_config():
    """Load test fixtures and expected values from config."""
    config_path = Path(__file__).resolve().parent / "test_config.yaml"
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def test_config():
    return _load_test_config()


class TestOutputType:
    """Tests for OUTPUT_TYPE and OUTPUT_TYPE_EXTENDED character generation."""

    def test_output_type_numeric_accepts_only_digits(self):
        """OUTPUT_TYPE.NUMERIC accepts only 0-9."""
        for i in range(256):
            c = chr(i)
            match_number = "0" <= c <= "9"
            result = OUTPUT_TYPE.NUMERIC.generate_character(i)
            assert result == (c if match_number else None)

    def test_output_type_alphanumeric_accepts_letters_and_digits(self):
        """OUTPUT_TYPE.ALPHANUMERIC accepts a-z, A-Z, 0-9 (no underscore in standard)."""
        for i in range(256):
            c = chr(i)
            match_num = "0" <= c <= "9"
            match_lower = "a" <= c <= "z"
            match_upper = "A" <= c <= "Z"
            match_alphanumeric = match_num or match_lower or match_upper
            result = OUTPUT_TYPE.ALPHANUMERIC.generate_character(i)
            assert result == (c if match_alphanumeric else None)

    def test_output_type_alphanumericplus_accepts_extended_set(self):
        """OUTPUT_TYPE.ALPHANUMERICPLUS adds & @ ! = + - ? and underscore."""
        special = {"&", "@", "!", "=", "+", "-", "?", "_"}
        for i in range(256):
            c = chr(i)
            match_num = "0" <= c <= "9"
            match_lower = "a" <= c <= "z"
            match_upper = "A" <= c <= "Z"
            match_alphanumeric = match_num or match_lower or match_upper
            match_alphanumericplus = match_alphanumeric or c in special
            result = OUTPUT_TYPE.ALPHANUMERICPLUS.generate_character(i)
            assert result == (c if match_alphanumericplus else None)

    def test_output_type_extended_numeric_maps_indices_to_digits(self):
        """OUTPUT_TYPE_EXTENDED with NUMERIC maps index j to chr('0'+j)."""
        ot = OUTPUT_TYPE_EXTENDED([CHARACTER_TYPE.NUMERIC])
        for j in range(10):
            assert ot.generate_character(j) == chr(ord("0") + j)


class TestPassveurd:
    """Tests for Passveurd password generator."""

    def test_passveurd_expected_outputs(self, test_config):
        """Generated passwords match reference outputs for each OUTPUT_TYPE."""
        cfg = test_config["passveurd"]
        expected = cfg["expected_outputs"]
        derived_keys = {
            ot: Passveurd(
                cfg["domain"],
                cfg["version"],
                cfg["pass_len"],
                ot,
                metadata=PasswordMetaData(),
            ).generate_password(cfg["secret"])
            for ot in OUTPUT_TYPE
        }
        assert derived_keys[OUTPUT_TYPE.NUMERIC] == expected["NUMERIC"]
        assert derived_keys[OUTPUT_TYPE.ALPHANUMERIC] == expected["ALPHANUMERIC"]
        assert derived_keys[OUTPUT_TYPE.ALPHANUMERICPLUS] == expected["ALPHANUMERICPLUS"]

    def test_passveurd_offset_slicing(self, test_config):
        """Password with offset matches substring of full output."""
        cfg = test_config["passveurd"]
        full_outputs = {
            ot: Passveurd(
                cfg["domain"],
                cfg["version"],
                cfg["pass_len"],
                ot,
                metadata=PasswordMetaData(),
            ).generate_password(cfg["secret"])
            for ot in OUTPUT_TYPE
        }
        for offset in range(10):
            for ot in OUTPUT_TYPE:
                pg = Passveurd(
                    cfg["domain"],
                    cfg["version"],
                    cfg["pass_len"] - offset,
                    ot,
                    offset=offset,
                    metadata=PasswordMetaData(),
                )
                result = pg.generate_password(cfg["secret"])
                assert result == full_outputs[ot][offset : cfg["pass_len"]]

    def test_passveurd_deterministic(self, test_config):
        """Same inputs produce same password."""
        cfg = test_config["passveurd"]
        pg = Passveurd(
            cfg["domain"],
            cfg["version"],
            16,
            OUTPUT_TYPE.ALPHANUMERICPLUS,
            metadata=PasswordMetaData(),
        )
        pw1 = pg.generate_password(cfg["secret"])
        pw2 = pg.generate_password(cfg["secret"])
        assert pw1 == pw2
        assert len(pw1) == 16

    def test_passveurd_different_secrets_different_outputs(self, test_config):
        """Different secrets produce different passwords."""
        cfg = test_config["passveurd"]
        pg = Passveurd(
            cfg["domain"],
            cfg["version"],
            16,
            OUTPUT_TYPE.ALPHANUMERICPLUS,
            metadata=PasswordMetaData(),
        )
        pw1 = pg.generate_password(cfg["secret"])
        pw2 = pg.generate_password("other_secret")
        assert pw1 != pw2

    def test_passveurd_extended_mode_character_coverage(self, test_config):
        """Extended mode with LOWER, UPPER, NUMERIC yields at least one of each."""
        output_type = OUTPUT_TYPE_EXTENDED(
            [CHARACTER_TYPE.LOWER, CHARACTER_TYPE.UPPER, CHARACTER_TYPE.NUMERIC]
        )
        pg = Passveurd(
            test_config["passveurd"]["domain"],
            0,
            12,
            output_type,
            metadata=PasswordMetaData(),
        )
        pw = pg.generate_password(test_config["passveurd"]["secret"])
        assert len(pw) == 12
        assert any(c.islower() for c in pw)
        assert any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw)


class TestPINConfig:
    """Tests for Passveurd PIN configuration generation."""

    def test_pin_config_roundtrip(self, test_config):
        """Generated PIN config produces the target PIN when used."""
        cfg = test_config["pin_config"]
        passveurd, n_found = Passveurd(
            cfg["domain"],
            cfg["version"],
            4,
            OUTPUT_TYPE_EXTENDED.NumericFast(),
        ).generate_PIN_config(cfg["secret"], cfg["pin_target"], cfg["max_offset"])
        assert passveurd.generate_password(cfg["secret"]) == cfg["pin_target"]
        assert n_found > 0

    def test_pin_config_roundtrip_with_offset(self, test_config):
        """PIN config works when base passveurd has non-zero offset."""
        cfg = test_config["pin_config"]
        passveurd, n_found = Passveurd(
            cfg["domain"],
            cfg["version"],
            4,
            OUTPUT_TYPE_EXTENDED.NumericFast(),
            offset=1000,
        ).generate_PIN_config(cfg["secret"], cfg["pin_target"], cfg["max_offset"])
        assert passveurd.generate_password(cfg["secret"]) == cfg["pin_target"]
        assert n_found > 0


class TestCryptoPass:
    """Tests for CryptoPass password generator."""

    def test_cryptopass_expected_output(self, test_config):
        """Generated password matches reference output."""
        cfg = test_config["cryptopass"]
        cp = CryptoPass(
            cfg["user"],
            cfg["url"],
            cfg["pass_len"],
            PasswordMetaData(),
        )
        result = cp.generate_password(cfg["secret"])
        assert result == cfg["expected_output"]

    def test_cryptopass_deterministic(self, test_config):
        """Same inputs produce same password."""
        cfg = test_config["cryptopass"]
        cp = CryptoPass(cfg["user"], cfg["url"], cfg["pass_len"], PasswordMetaData())
        pw1 = cp.generate_password(cfg["secret"])
        pw2 = cp.generate_password(cfg["secret"])
        assert pw1 == pw2
        assert len(pw1) == cfg["pass_len"]

    def test_cryptopass_different_user_url_different_password(self, test_config):
        """Different user/URL produces different password."""
        cfg = test_config["cryptopass"]
        cp1 = CryptoPass(cfg["user"], cfg["url"], 20, PasswordMetaData())
        cp2 = CryptoPass("other_user", "other.com", 20, PasswordMetaData())
        pw1 = cp1.generate_password(cfg["secret"])
        pw2 = cp2.generate_password(cfg["secret"])
        assert pw1 != pw2
