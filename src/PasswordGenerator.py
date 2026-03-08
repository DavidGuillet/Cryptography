"""Password generation using PBKDF2 + RC4 stream cipher.

Classes
-------
CharacterType
    Enumeration of supported character categories.
OutputType
    Standard output type with fixed character sets (IntEnum).
OutputTypeExtended
    Extended output type backed by an explicit list of CharacterType members.
RC4
    RC4 stream cipher with configurable initial keystream drop.
PasswordMetaData
    Metadata attached to a saved password entry.
PasswordGenerator
    Abstract base for PBKDF2-based password generators.
Passveurd
    PBKDF2 + RC4 password generator keyed by domain and version.
CryptoPass
    PBKDF2 + Base64 password generator keyed by username and URL.
"""

import hashlib
import binascii
import re
import functools
import datetime
from copy import deepcopy
from enum import IntEnum
from secrets import randbelow
from typing import Optional

# RC4 drop constants — initial keystream bytes are discarded to reduce known biases.
_RC4_DROP_HIGH = 378
_RC4_DROP_LOW = 247


class CharacterType(IntEnum):
    """Enumeration of supported character categories for password generation."""

    LOWER = 0
    UPPER = 1
    NUMERIC = 2
    SPECIAL = 3

    @staticmethod
    def tips() -> list:
        """Return human-readable descriptions of each character type."""
        return [
            "Lowercase characters ( e.g. abcdef )",
            "Uppercase characters ( e.g. ABCDEF )",
            "Numbers ( e.g. 123456 )",
            "Symbols ( {} )".format("".join(CharacterType._special_characters())),
        ]

    @staticmethod
    def from_char(c: str) -> Optional["CharacterType"]:
        """Return the CharacterType that contains *c*, or None if unrecognised."""
        for ct in CharacterType:
            if c in ct.char_list():
                return ct
        return None

    @functools.lru_cache(maxsize=None)
    def char_list(self) -> list:
        """Return the list of characters belonging to this type (cached per member)."""
        if self in (CharacterType.LOWER, CharacterType.UPPER, CharacterType.NUMERIC):
            start, end = self._start_end_characters()
            return [chr(i) for i in range(ord(start), ord(end) + 1)]
        if self == CharacterType.SPECIAL:
            return CharacterType._special_characters()
        raise ValueError(f"Unrecognised CharacterType: {self!r}")

    # --- private helpers ---

    @staticmethod
    def _special_characters() -> list:
        return ["&", "@", "!", "=", "+", "-", "?"]

    def _start_end_characters(self) -> tuple:
        if self == CharacterType.NUMERIC:
            return "0", "9"
        if self == CharacterType.LOWER:
            return "a", "z"
        if self == CharacterType.UPPER:
            return "A", "Z"
        raise ValueError(f"No start/end character for CharacterType {self.name!r}")


# OutputType and OutputTypeExtended share the same interface (is_extended /
# generate_character) but intentionally do not inherit from a common base class
# — OutputType is an IntEnum for backward-compatible serialisation, while
# OutputTypeExtended is a plain class with richer state.


class OutputType(IntEnum):
    """Standard output type with fixed character sets.

    Values 0/1/2 match the legacy Passveurd plist — do **not** change.
    """

    # numbering 0/1/2 defined from Passveurd plist. do not change
    ALPHANUMERIC = 0
    NUMERIC = 1
    ALPHANUMERICPLUS = 2

    def is_extended(self) -> bool:
        """Return False; this is a standard (non-extended) output type."""
        return False

    def generate_character(self, idx: int) -> Optional[str]:
        """Return the character for *idx* if accepted by this type, else None."""
        if self == OutputType.NUMERIC:
            pattern = r"\d"
        elif self == OutputType.ALPHANUMERIC:
            pattern = r"[^\W_]"
        elif self == OutputType.ALPHANUMERICPLUS:
            pattern = r"[\w&@!=\+\-\?]"
        else:
            raise ValueError(f"Unsupported OutputType value: {self.value!r}")
        c = chr(idx)
        return c if re.match(pattern, c, re.ASCII) else None


class OutputTypeExtended:
    """Extended output type backed by an explicit list of CharacterType members.

    Args:
        character_types: The character categories to include in the password.
    """

    def __init__(self, character_types: list) -> None:
        self.name = "EXTENDED"
        self.character_types = character_types
        self.characters: list = []
        for ct in character_types:
            self.characters += ct.char_list()
        self.max_num_characters = len(self.characters)

    @classmethod
    def NumericFast(cls) -> "OutputTypeExtended":
        """Convenience constructor for a numeric-only extended output type."""
        return cls([CharacterType.NUMERIC])

    def __eq__(self, other: object) -> bool:
        return self.__dict__ == other.__dict__

    def is_extended(self) -> bool:
        """Return True."""
        return True

    def generate_character(self, idx: int) -> str:
        """Return the character at position *idx* in the allowed character list.

        Args:
            idx: Index into the character list (0 <= idx < max_num_characters).

        Raises:
            IndexError: If *idx* is out of range.
        """
        if idx >= self.max_num_characters:
            raise IndexError(
                f"Index {idx} is out of range; must be < {self.max_num_characters}"
            )
        return self.characters[idx]


class RC4:
    """RC4 stream cipher with configurable initial keystream drop.

    A number of initial keystream bytes (determined by the last byte of the
    derived key) are discarded to reduce known RC4 biases.  See
    ``_RC4_DROP_HIGH`` and ``_RC4_DROP_LOW`` for the exact drop counts used.

    Args:
        dk: Derived key as a bytes-like sequence of integers (0-255).
    """

    def __init__(self, dk: bytes) -> None:
        drop = _RC4_DROP_HIGH if dk[-1] & 1 else _RC4_DROP_LOW
        # Key-scheduling algorithm (KSA)
        self.key = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.key[i] + dk[i % len(dk)]) % 256
            self.key[i], self.key[j] = self.key[j], self.key[i]
        # Initialise indices and drop initial keystream bytes
        self.idx_i = 0
        self.idx_j = 0
        for _ in range(-drop, 0):
            self.generate_next()

    def generate_next(self, max_num: Optional[int] = None) -> int:
        """Generate the next value from the keystream.

        Args:
            max_num: If given, return a value in ``[0, max_num)``.  Must be
                between 1 and 256 inclusive.  If None, return a raw byte (0-255).

        Returns:
            An integer in ``[0, max_num)`` (or ``[0, 256)`` if *max_num* is None).

        Raises:
            ValueError: If *max_num* is less than 1.
        """
        if max_num is not None:
            if max_num < 1:
                raise ValueError("max_num must be >= 1")
            max_num = min(max_num, 256)
        while True:
            self.idx_i = (self.idx_i + 1) % 256
            self.idx_j = (self.idx_j + self.key[self.idx_i]) % 256
            self.key[self.idx_i], self.key[self.idx_j] = (
                self.key[self.idx_j],
                self.key[self.idx_i],
            )
            idx = self.key[(self.key[self.idx_i] + self.key[self.idx_j]) % 256]
            if max_num is None:
                return idx
            if idx < (256 // max_num) * max_num:
                return idx % max_num


class PasswordMetaData:
    """Metadata attached to a saved password entry.

    Args:
        note:          Free-text note.
        category:      Category label used for grouping entries.
        last_modified: Date the entry was last changed; defaults to today.

    Note:
        Equality (``__eq__``) is intentionally content-based: it compares
        ``category`` and ``note`` only.  ``last_modified`` is excluded so that
        re-generating the same password with the same inputs is considered equal
        regardless of the timestamp.
    """

    def __init__(
        self,
        note: str = "",
        category: Optional[str] = None,
        last_modified: Optional[datetime.date] = None,
    ) -> None:
        self.note = note
        self.category = category
        self.last_modified = (
            last_modified if last_modified is not None else datetime.date.today()
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PasswordMetaData):
            return NotImplemented
        return self.category == other.category and (
            (not self.note and not other.note) or self.note == other.note
        )


class PasswordGenerator:
    """Abstract base for PBKDF2-based password generators.

    Subclasses must implement ``_get_PBKDF2_salt_and_pass`` and
    ``_get_generated_password_from_derived_key``.

    Args:
        offset:      Number of leading characters to skip in the generated stream.
        pass_len:    Length of the final password.
        hash_name:   HMAC digest name passed to :func:`hashlib.pbkdf2_hmac`.
        iterations:  PBKDF2 iteration count.
        dk_len:      Derived-key length in bytes.
        metadata:    Metadata for this entry.
    """

    def __init__(
        self,
        offset: int,
        pass_len: int,
        hash_name: str,
        iterations: int,
        dk_len: int,
        metadata: "PasswordMetaData",
    ) -> None:
        self.offset = offset
        self.pass_len = pass_len
        self.hash_name = hash_name
        self.iterations = iterations
        self.dk_len = dk_len
        self.metadata = metadata

    def generate_password(self, password: str) -> str:
        """Generate a password from the master *password*.

        Uses PBKDF2 to derive a key, then delegates to the subclass's
        :meth:`_get_generated_password_from_derived_key`.

        Args:
            password: The user's master password / secret.

        Returns:
            The generated password string.
        """
        salt, pw = self._get_PBKDF2_salt_and_pass(password)
        dk = hashlib.pbkdf2_hmac(
            self.hash_name, pw.encode(), salt.encode(), self.iterations, self.dk_len
        )
        return self._get_generated_password_from_derived_key(dk)[
            self.offset : self.offset + self.pass_len
        ]


class Passveurd(PasswordGenerator):
    """PBKDF2 + RC4 password generator keyed by domain and version.

    The algorithm has two steps:

    1. PBKDF2 produces a derived key (8-bit binary vector <= 256 bytes).
    2. RC4 stream cipher maps the derived key to the final password.

    Args:
        domain:      Service / domain name used as the PBKDF2 password input.
        version:     Integer version, incremented to rotate the password.
        pass_len:    Desired password length.
        output_type: A :class:`OutputType` or :class:`OutputTypeExtended` instance.
        offset:      Skip this many leading characters in the generated stream.
        hash_name:   HMAC digest name (``"sha1"`` or ``"sha256"``).
        iterations:  PBKDF2 iteration count.
        dk_len:      Derived-key length in bytes.
        metadata:    Optional :class:`PasswordMetaData` for this entry.
    """

    tab_name = "Passveurd"

    def __init__(
        self,
        domain: str,
        version: int,
        pass_len: int,
        output_type,
        offset: int = 0,
        hash_name: str = "sha1",
        iterations: int = 10000,
        dk_len: int = 32,
        metadata: Optional[PasswordMetaData] = None,
    ) -> None:
        if metadata is None:
            metadata = PasswordMetaData()
        super().__init__(offset, pass_len, hash_name, iterations, dk_len, metadata)
        self.domain = domain
        self.version = int(version)
        self.output_type = output_type
        if output_type.is_extended():
            if pass_len < 4:
                raise ValueError(
                    "Password length with EXTENDED output type must be >= 4"
                )
            if not getattr(output_type, "characters", None):
                raise ValueError(
                    "Must provide at least one character type in extended mode"
                )

    def generate_PIN_config(
        self,
        password: str,
        pin: str,
        max_offset: int = 100000,
        max_attempts: int = 10_000,
    ) -> tuple:
        """Find a (version, offset) pair so that :meth:`generate_password` returns *pin*.

        Only supported for ``OutputTypeExtended.NumericFast()`` with a 4-digit PIN.

        Args:
            password:     The user's master password / secret.
            pin:          The target PIN string (e.g. ``"1234"``).
            max_offset:   Maximum offset to search within the generated stream.
            max_attempts: Maximum random-version attempts before giving up.

        Returns:
            A ``(new_passveurd, n_found)`` tuple where *n_found* is the number of
            matching offsets found in the last successful attempt.

        Raises:
            ValueError:   If called on an incompatible output type or pass_len.
            RuntimeError: If no configuration is found within *max_attempts*.
        """
        if self.output_type != OutputTypeExtended.NumericFast() or self.pass_len > 4:
            raise ValueError(
                "PIN config generation requires OutputTypeExtended with NUMERIC only "
                "and pass_len <= 4"
            )
        target_len = len(pin)
        new_passveurd = deepcopy(self)
        new_passveurd.offset = 0
        new_passveurd.pass_len = max_offset + target_len
        # 100000 offsets give enough matches to avoid leaking pattern on first find
        pattern = re.compile(f"({re.escape(pin)})")
        for _ in range(max_attempts):
            new_passveurd.version = randbelow(2**32) + 1
            dk = new_passveurd.generate_password(password)
            offsets_found = [m.start() for m in pattern.finditer(dk)]
            if offsets_found:
                rnd_idx = randbelow(len(offsets_found))
                new_passveurd.offset = offsets_found[rnd_idx]
                new_passveurd.pass_len = target_len
                return new_passveurd, len(offsets_found)
        raise RuntimeError(
            f"PIN configuration not found after {max_attempts} attempts."
        )

    def get_key(self) -> str:
        return self.domain

    def is_legacy(self) -> bool:
        return (
            self.offset == 0
            and self.hash_name == "sha1"
            and self.iterations == 10000
            and self.dk_len == 32
            and not self.output_type.is_extended()
        )

    def __eq__(self, other: object) -> bool:
        return self.__dict__ == other.__dict__

    def _get_PBKDF2_salt_and_pass(self, password: str) -> tuple:
        salt = password
        pw = f"{self.domain}{self.version}"
        return salt, pw

    def _get_generated_password_from_derived_key(self, dk: bytes) -> str:
        """Generate a character stream from the RC4 cipher seeded by *dk*.

        In extended mode, ensures that at least one character from each requested
        CharacterType is present in the output, replacing characters as needed
        using the cipher stream to select positions deterministically.

        Args:
            dk: Derived key bytes from PBKDF2.

        Returns:
            The full generated string (before offset/length slicing).
        """
        output: list = []
        stream_cipher = RC4(dk)
        max_num_characters = (
            self.output_type.max_num_characters if self.output_type.is_extended() else None
        )
        while len(output) < self.pass_len + self.offset:
            c = self.output_type.generate_character(
                stream_cipher.generate_next(max_num_characters)
            )
            if c is not None:
                output.append(c)

        if self.output_type.is_extended():
            # Check if all character types are represented; replace using stream cipher
            generated_types = [CharacterType.from_char(c) for c in output]
            chars_per_type = {
                ct: [i for i, t in enumerate(generated_types) if t == ct]
                for ct in self.output_type.character_types
            }
            available = list(range(self.pass_len + self.offset))
            # Protect one representative character per present type
            for ct, indices in chars_per_type.items():
                if indices:
                    protected = indices[stream_cipher.generate_next(len(indices))]
                    available.remove(protected)
            # Replace a slot for each missing type
            for ct, indices in chars_per_type.items():
                if not indices:
                    slot = available[stream_cipher.generate_next(len(available))]
                    available.remove(slot)
                    single_type_ot = OutputTypeExtended([ct])
                    output[slot] = single_type_ot.generate_character(
                        stream_cipher.generate_next(single_type_ot.max_num_characters)
                    )
        return "".join(output)


class CryptoPass(PasswordGenerator):
    """PBKDF2 + Base64 password generator keyed by username and URL.

    Uses fixed parameters: SHA-256, 5 000 iterations, 25-byte derived key.

    Args:
        user_name: Username / login identifier.
        url:       Service URL.
        pass_len:  Desired password length.
        metadata:  Optional :class:`PasswordMetaData` for this entry.
    """

    tab_name = "CryptoPass"
    _HASH_NAME = "sha256"
    _ITERATIONS = 5000
    _DK_LEN = 25

    def __init__(
        self,
        user_name: str,
        url: str,
        pass_len: int,
        metadata: Optional[PasswordMetaData] = None,
    ) -> None:
        if metadata is None:
            metadata = PasswordMetaData()
        super().__init__(
            0, pass_len, self._HASH_NAME, self._ITERATIONS, self._DK_LEN, metadata
        )
        self.user_name = user_name
        self.url = url

    def get_key(self) -> str:
        return f"{self.user_name}@{self.url}"

    def _get_PBKDF2_salt_and_pass(self, password: str) -> tuple:
        salt = f"{self.user_name}@{self.url}"
        pw = password
        return salt, pw

    def _get_generated_password_from_derived_key(self, dk: bytes) -> str:
        return binascii.b2a_base64(dk).decode()
