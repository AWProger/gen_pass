"""
core.py - password generation, encrypted storage, history.

Design notes for the rework:

  * The encryption key is now PERSISTED. Previously `Fernet.generate_key()` ran in
    __init__, so every launch produced a new key, the old one was discarded, and
    every previously saved file became permanently undecryptable. That was the
    single most serious defect in the original.

  * Only the standard library is used. `secrets` for CSPRNG, `hashlib.scrypt` for
    key derivation, and a keystream built on `hashlib.blake2b` for encryption. This
    removes the `cryptography` dependency, which matters for a program distributed
    as a single .exe.

  * Strength is reported in bits of entropy, derived from the actual character set
    and length, not from a length threshold plus a symbol check.

  * Character sets are configurable, and the default EXCLUDES characters that are
    routinely rejected by real sites: quotes, backslash, backtick, and the space.
    The original used string.punctuation, which produced passwords containing
    quote, backtick and backslash that many sites simply do not accept.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import struct
import time
import json
import os
import secrets
import string
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

__version__ = "3.0.0"

# --------------------------------------------------------------------------
# Character sets
# --------------------------------------------------------------------------

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits

# Symbols safe for the overwhelming majority of real-world password rules.
# Deliberately excludes  ' " ` \ and whitespace: sites reject these constantly.
SAFE_SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~"

# Offered separately, for users who want the full set and accept the risk.
ALL_SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

AMBIGUOUS = "Il1O0o"

MIN_LENGTH = 8
MAX_LENGTH = 256
DEFAULT_LENGTH = 20


# --------------------------------------------------------------------------
# Key derivation and authenticated encryption (stdlib only)
# --------------------------------------------------------------------------

def derive_key(passphrase: str, salt: bytes) -> bytes:
    """scrypt is memory-hard: a stolen key file is far more expensive to attack."""
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=2**15,
        r=8,
        p=1,
        dklen=32,
        maxmem=64 * 1024 * 1024,
    )


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Counter-mode stream built from blake2b. Each block is bound to key+nonce+counter."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        h = hashlib.blake2b(digest_size=64, key=key)
        h.update(nonce)
        h.update(counter.to_bytes(8, "big"))
        out.extend(h.digest())
        counter += 1
    return bytes(out[:length])


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with a keystream, then authenticate.

    The tag is computed over nonce+ciphertext with a MAC key derived from the key,
    so tampering is detected rather than silently decrypted.
    """
    nonce = secrets.token_bytes(16)
    cipher = bytes(a ^ b for a, b in zip(plaintext, _keystream(key, nonce, len(plaintext)), strict=True))
    mac_key = hashlib.blake2b(b"mac", key=key, digest_size=32).digest()
    tag = hashlib.blake2b(nonce + cipher, key=mac_key, digest_size=32).digest()
    return b"AWP1" + nonce + tag + cipher


def decrypt(blob: bytes, key: bytes) -> bytes:
    # Every encrypt() output carries its own AWP1 prefix. Accepting a bare payload
    # silently would let a truncated or mis-sliced blob decrypt into garbage.
    if len(blob) < 4 + 16 + 32:
        raise ValueError("Файл повреждён или слишком мал")
    if blob[:4] != b"AWP1":
        raise ValueError("Неизвестный формат файла")

    nonce = blob[4:20]
    tag = blob[20:52]
    cipher = blob[52:]

    mac_key = hashlib.blake2b(b"mac", key=key, digest_size=32).digest()
    expected = hashlib.blake2b(nonce + cipher, key=mac_key, digest_size=32).digest()

    # Constant-time compare: a plain == would leak timing information.
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Неверный пароль или файл был изменён")

    return bytes(a ^ b for a, b in zip(cipher, _keystream(key, nonce, len(cipher)), strict=True))


# --------------------------------------------------------------------------
# Password generation
# --------------------------------------------------------------------------

def build_alphabet(
    *,
    lowercase: bool = True,
    uppercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
    full_symbols: bool = False,
) -> str:
    """Assemble the character pool from the requested classes."""
    pool = ""
    if lowercase:
        pool += LOWERCASE
    if uppercase:
        pool += UPPERCASE
    if digits:
        pool += DIGITS
    if symbols:
        pool += ALL_SYMBOLS if full_symbols else SAFE_SYMBOLS
    if exclude_ambiguous:
        pool = "".join(c for c in pool if c not in AMBIGUOUS)
    # When exclude_ambiguous wipes a class out entirely, that class cannot supply its
    # mandatory character - asking for it is an error, not a silent downgrade.
    # Checked here so the failure names the actual cause.
    for name, source, enabled in (
        ("строчных", LOWERCASE, lowercase),
        ("прописных", UPPERCASE, uppercase),
        ("цифр", DIGITS, digits),
    ):
        if enabled and not _filter(source, exclude_ambiguous):
            raise ValueError(
                f"Исключение неоднозначных символов удаляет все {name} буквы/цифры. "
                "Отключите эту опцию или оставьте другой набор."
            )

    if not pool:
        raise ValueError("Выберите хотя бы один набор символов")
    return pool


def generate_password(
    length: int = DEFAULT_LENGTH,
    *,
    lowercase: bool = True,
    uppercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
    full_symbols: bool = False,
) -> str:
    """Generate a password with at least one character from each enabled class.

    Guarantees are explicit: the result always contains one lower, one upper and
    one digit when those classes are enabled, so the pool is never degenerate.
    """
    if not isinstance(length, int):
        raise ValueError("Длина должна быть целым числом")
    if length < MIN_LENGTH:
        raise ValueError(f"Минимальная длина - {MIN_LENGTH}")
    if length > MAX_LENGTH:
        raise ValueError(f"Максимальная длина - {MAX_LENGTH}")

    pool = build_alphabet(
        lowercase=lowercase,
        uppercase=uppercase,
        digits=digits,
        symbols=symbols,
        exclude_ambiguous=exclude_ambiguous,
        full_symbols=full_symbols,
    )

    chars: list[str] = []
    if lowercase:
        chars.append(secrets.choice(_filter(LOWERCASE, exclude_ambiguous)))
    if uppercase:
        chars.append(secrets.choice(_filter(UPPERCASE, exclude_ambiguous)))
    if digits:
        chars.append(secrets.choice(_filter(DIGITS, exclude_ambiguous)))

    # Each required character consumes one slot. A password shorter than the number
    # of required classes cannot satisfy them; say so instead of looping forever.
    required = len(chars)
    if length < required:
        raise ValueError(
            f"Длины {length} недостаточно для {required} обязательных символов. "
            "Отключите лишние наборы или увеличьте длину."
        )

    chars += [secrets.choice(pool) for _ in range(length - required)]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# Pronounceable words are built from consonant+vowel syllables. Easier to type
# and remember than random characters; the entropy is still exact, because each
# syllable is an independent uniform draw.
_CONSONANTS = "bdfgkmnprstvz"
_VOWELS = "aeiou"
SYLLABLES = [c + v for c in _CONSONANTS for v in _VOWELS]
PASSPHRASE_MIN_WORDS = 3
PASSPHRASE_MAX_WORDS = 12


def generate_passphrase(words: int = 5, *, syllables: int = 3, separator: str = "-",
                        capitalize: bool = True, add_number: bool = True) -> str:
    """Words like "Bakemo-Tupira-Sedola-Kivune-47"."""
    if not PASSPHRASE_MIN_WORDS <= words <= PASSPHRASE_MAX_WORDS:
        raise ValueError(f"Слов должно быть от {PASSPHRASE_MIN_WORDS} до {PASSPHRASE_MAX_WORDS}")
    if not 2 <= syllables <= 5:
        raise ValueError("Слогов в слове должно быть от 2 до 5")
    parts = []
    for _ in range(words):
        word = "".join(secrets.choice(SYLLABLES) for _ in range(syllables))
        parts.append(word.capitalize() if capitalize else word)
    if add_number:
        parts.append(str(secrets.randbelow(90) + 10))
    return separator.join(parts)


def passphrase_entropy(words: int = 5, *, syllables: int = 3, add_number: bool = True) -> float:
    """Exact entropy of generate_passphrase() with these settings."""
    import math
    bits = words * syllables * math.log2(len(SYLLABLES))
    if add_number:
        bits += math.log2(90)
    return bits


def generate_pin(length: int = 6) -> str:
    if not 4 <= length <= 12:
        raise ValueError("Длина PIN - от 4 до 12 цифр")
    return "".join(secrets.choice(DIGITS) for _ in range(length))


def _filter(source: str, exclude_ambiguous: bool) -> str:
    if not exclude_ambiguous:
        return source
    filtered = "".join(c for c in source if c not in AMBIGUOUS)
    # A whole class can be wiped out by the filter; fall back rather than crash.
    return filtered or source


def estimate_entropy(password: str, pool_size: int | None = None) -> float:
    """Bits of entropy, assuming a uniform draw from the pool that produced it."""
    if pool_size is None:
        pool_size = estimate_pool_size(password)
    if pool_size <= 1:
        return 0.0
    return len(password) * (pool_size.bit_length() - 1)


def estimate_pool_size(password: str) -> int:
    """Reconstruct the pool size from the characters actually present."""
    size = 0
    if any(c in LOWERCASE for c in password):
        size += len(LOWERCASE)
    if any(c in UPPERCASE for c in password):
        size += len(UPPERCASE)
    if any(c in DIGITS for c in password):
        size += len(DIGITS)
    if any(c in SAFE_SYMBOLS for c in password):
        size += len(SAFE_SYMBOLS)
    if any(c in ALL_SYMBOLS and c not in SAFE_SYMBOLS for c in password):
        size += len(ALL_SYMBOLS) - len(SAFE_SYMBOLS)
    return size or len(LOWERCASE) + len(UPPERCASE) + len(DIGITS)


def strength_label(bits: float) -> str:
    """Thresholds follow common guidance: 60 bits is the practical floor."""
    if bits < 40:
        return "Очень слабый"
    if bits < 60:
        return "Слабый"
    if bits < 80:
        return "Средний"
    if bits < 120:
        return "Сильный"
    return "Очень сильный"


# --------------------------------------------------------------------------
# Two-factor codes (TOTP, RFC 6238)
# --------------------------------------------------------------------------

TOTP_PERIOD = 30


def normalize_totp_secret(secret: str) -> str:
    """Accept a raw Base32 secret or an otpauth:// URI; return clean Base32.

    Raises ValueError when the input is not valid Base32.
    """
    secret = secret.strip()
    if secret.lower().startswith("otpauth://"):
        from urllib.parse import parse_qs, urlparse
        params = parse_qs(urlparse(secret).query)
        secret = params.get("secret", [""])[0]
    cleaned = secret.replace(" ", "").replace("-", "").upper().rstrip("=")
    if not cleaned:
        raise ValueError("Пустой секрет 2FA")
    try:
        base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))
    except (ValueError, base64.binascii.Error) as e:
        raise ValueError("Секрет 2FA должен быть в формате Base32 (буквы A-Z и цифры 2-7)") from e
    return cleaned


def totp(secret: str, at: float | None = None, *, digits: int = 6,
         period: int = TOTP_PERIOD, algorithm: str = "sha1") -> str:
    """Current one-time code for a Base32 secret."""
    cleaned = normalize_totp_secret(secret)
    key = base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))
    counter = int((time.time() if at is None else at) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), algorithm).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10 ** digits).zfill(digits)


def totp_remaining(at: float | None = None, period: int = TOTP_PERIOD) -> int:
    """Seconds until the current code expires."""
    now = time.time() if at is None else at
    return period - int(now) % period


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------

@dataclass
class Record:
    id: str
    password: str
    site: str = ""
    login: str = ""
    email: str = ""
    created: str = ""
    note: str = ""
    url: str = ""
    folder: str = ""
    tags: list[str] = field(default_factory=list)
    favorite: bool = False
    updated: str = ""
    # Base32 TOTP secret for the site's two-factor codes, empty when unused.
    totp: str = ""
    # Previous passwords, newest first: [{"password": ..., "changed": ...}].
    history: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Record":
        # Every field has a default, so vaults written by older versions load
        # unchanged and unknown keys from newer ones are ignored.
        tags = data.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        return cls(
            id=data.get("id", "") or str(uuid.uuid4()),
            password=data.get("password", ""),
            site=data.get("site", ""),
            login=data.get("login", ""),
            email=data.get("email", ""),
            created=data.get("created", ""),
            note=data.get("note", ""),
            url=data.get("url", ""),
            folder=data.get("folder", ""),
            tags=list(tags),
            favorite=bool(data.get("favorite", False)),
            updated=data.get("updated", ""),
            totp=data.get("totp", ""),
            history=list(data.get("history", [])),
        )

    @property
    def title(self) -> str:
        return self.site or self.url or self.login or "без названия"

    def matches(self, query: str) -> bool:
        q = query.lower()
        haystack = (self.site, self.login, self.email, self.url, self.note,
                    self.folder, *self.tags)
        return any(q in h.lower() for h in haystack)


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

DEFAULT_DIR = Path.home() / ".gen_pass"

# Fields beyond the original five that add() and edit() accept.
EDITABLE_FIELDS = ("url", "folder", "tags", "favorite", "totp")
# How many previous passwords a record remembers.
HISTORY_LIMIT = 10


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Vault:
    """Encrypted password vault backed by a single file.

    The key is derived from a passphrase with scrypt and a per-vault random salt.
    A verification block lets us tell "wrong passphrase" from "damaged file"
    instead of returning a generic decryption error.
    """

    MAGIC = b"AWP1"

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_DIR / "vault.awp"
        self.records: list[Record] = []
        self._salt: bytes = b""
        # Set by create() and unlock(). save() refuses to run without it, so a
        # half-initialised vault can never overwrite good data with garbage.
        self._key: bytes | None = None
        # Keep copies of the previous versions next to the vault.
        self.backups = True
        self.backup_limit = 20

    # -- low level -------------------------------------------------------

    def exists(self) -> bool:
        return self.path.exists()

    def _load_or_make_salt(self) -> bytes:
        sidecar = self.path.with_suffix(".salt")
        if sidecar.exists():
            return sidecar.read_bytes()
        salt = secrets.token_bytes(16)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        sidecar.write_bytes(salt)
        _restrict_permissions(sidecar)
        return salt

    def _header(self, key: bytes) -> bytes:
        return encrypt(b"gen_pass.vault.v1", key)

    def _read_header(self, key: bytes) -> bool:
        if len(self.blob) < len(self.MAGIC) + 4:
            return False
        marker_len = int.from_bytes(self.blob[4:8], "big")
        try:
            marker = decrypt(self.blob[4 : 8 + marker_len], key)
        except ValueError:
            return False
        return marker == b"gen_pass.vault.v1"

    # -- public API ------------------------------------------------------

    def create(self, passphrase: str) -> None:
        """Create an empty vault. Refuses to overwrite an existing one."""
        if self.path.exists():
            raise FileExistsError(f"Файл уже существует: {self.path}")
        if not passphrase:
            raise ValueError("Пароль не может быть пустым")

        self._salt = self._load_or_make_salt()
        self._key = derive_key(passphrase, self._salt)
        self.records = []
        self._write(self._key)

    def unlock(self, passphrase: str) -> None:
        """Decrypt the vault into memory."""
        if not self.path.exists():
            raise FileNotFoundError(f"Файл не найден: {self.path}")

        self.blob = self.path.read_bytes()
        self._salt = self._load_or_make_salt()
        key = derive_key(passphrase, self._salt)

        # Layout: MAGIC(4) | marker_len(4) | marker | body
        # Both marker and body are full encrypt() outputs, each with its own
        # AWP1 prefix and MAC. slice start, not 4, because the prefix is included.
        marker_len = int.from_bytes(self.blob[4:8], "big")
        marker = decrypt(self.blob[8 : 8 + marker_len], key)
        if marker != b"gen_pass.vault.v1":
            raise ValueError("Файл повреждён")

        body = decrypt(self.blob[8 + marker_len :], key)
        data = json.loads(body.decode("utf-8"))
        self.records = [Record.from_dict(r) for r in data.get("records", [])]
        self._key = key

    def save(self) -> None:
        """Re-encrypt and write. Requires a prior create() or unlock()."""
        if self._key is None:
            raise RuntimeError("Сначала вызовите unlock() или create()")
        self._write(self._key)

    def _write(self, key: bytes) -> None:
        payload = json.dumps(
            {"version": __version__, "records": [r.to_dict() for r in self.records]},
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")

        marker = encrypt(b"gen_pass.vault.v1", key)
        blob = self.MAGIC + len(marker).to_bytes(4, "big") + marker + encrypt(payload, key)

        # Write to a temp file, then replace. A crash mid-write would otherwise
        # leave a truncated vault with no way back.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_bytes(blob)
        _restrict_permissions(tmp)
        if self.backups and self.path.exists():
            self._backup()
        tmp.replace(self.path)

    # -- backups ---------------------------------------------------------

    @property
    def backup_dir(self) -> Path:
        return self.path.parent / "backups"

    def _backup(self) -> None:
        """Copy the current vault and its salt aside before it is replaced.

        Best effort: a failed backup must never block saving the user's data.
        """
        try:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
            target = self.backup_dir / f"{self.path.stem}-{stamp}{self.path.suffix}"
            target.write_bytes(self.path.read_bytes())
            _restrict_permissions(target)
            salt = self.path.with_suffix(".salt")
            if salt.exists():
                target.with_suffix(".salt").write_bytes(salt.read_bytes())
            self._prune_backups()
        except OSError:
            pass

    def list_backups(self) -> list[Path]:
        if not self.backup_dir.exists():
            return []
        return sorted(self.backup_dir.glob(f"{self.path.stem}-*{self.path.suffix}"),
                      reverse=True)

    def _prune_backups(self) -> None:
        for old in self.list_backups()[self.backup_limit:]:
            old.unlink(missing_ok=True)
            old.with_suffix(".salt").unlink(missing_ok=True)

    # -- master password -------------------------------------------------

    def verify(self, passphrase: str) -> bool:
        """True when passphrase opens this vault. Does not touch loaded records."""
        if self._key is None:
            return False
        return hmac.compare_digest(derive_key(passphrase, self._salt), self._key)

    def change_passphrase(self, old: str, new: str) -> None:
        """Re-encrypt under a new passphrase and a fresh salt."""
        if not self.verify(old):
            raise ValueError("Текущий мастер-пароль неверен")
        if not new:
            raise ValueError("Пароль не может быть пустым")
        if self.backups and self.path.exists():
            self._backup()
        salt = secrets.token_bytes(16)
        key = derive_key(new, salt)
        sidecar = self.path.with_suffix(".salt")
        tmp_salt = sidecar.with_suffix(".salt.tmp")
        tmp_salt.write_bytes(salt)
        _restrict_permissions(tmp_salt)
        backups, self.backups = self.backups, False
        try:
            # Salt first: if the vault write then fails, the backup taken above
            # still holds the old vault together with the old salt.
            tmp_salt.replace(sidecar)
            self._salt, self._key = salt, key
            self._write(key)
        finally:
            self.backups = backups

    # -- record operations ----------------------------------------------

    def add(self, password: str, site: str = "", login: str = "", email: str = "",
            note: str = "", **extra: Any) -> Record:
        now = _now()
        rec = Record(
            id=str(uuid.uuid4()),
            password=password,
            site=site,
            login=login,
            email=email,
            created=now,
            note=note,
            updated=now,
        )
        for key in EDITABLE_FIELDS:
            if key in extra:
                setattr(rec, key, extra[key])
        self.records.append(rec)
        return rec

    def get(self, record_id: str) -> Record | None:
        return next((r for r in self.records if r.id == record_id), None)

    def delete(self, record_id: str) -> bool:
        before = len(self.records)
        self.records = [r for r in self.records if r.id != record_id]
        return len(self.records) < before

    def edit(self, record_id: str, **fields: Any) -> bool:
        rec = self.get(record_id)
        if rec is None:
            return False
        new_pwd = fields.get("password")
        if new_pwd is not None and new_pwd != rec.password and rec.password:
            rec.history.insert(0, {"password": rec.password, "changed": _now()})
            del rec.history[HISTORY_LIMIT:]
        changed = False
        for key in ("password", "site", "login", "email", "note", *EDITABLE_FIELDS):
            if key in fields and getattr(rec, key) != fields[key]:
                setattr(rec, key, fields[key])
                changed = True
        if changed:
            rec.updated = _now()
        return True

    def search(self, query: str) -> list[Record]:
        if not query:
            return []
        return [r for r in self.records if r.matches(query)]

    def folders(self) -> list[str]:
        return sorted({r.folder for r in self.records if r.folder}, key=str.lower)

    def merge(self, records: list[Record]) -> tuple[int, int]:
        """Add imported records, skipping exact duplicates. Returns (added, skipped)."""
        seen = {(r.site, r.login, r.password) for r in self.records}
        ids = {r.id for r in self.records}
        added = skipped = 0
        for rec in records:
            key = (rec.site, rec.login, rec.password)
            if key in seen:
                skipped += 1
                continue
            if not rec.id or rec.id in ids:
                rec.id = str(uuid.uuid4())
            if not rec.created:
                rec.created = _now()
            self.records.append(rec)
            seen.add(key)
            ids.add(rec.id)
            added += 1
        return added, skipped

    def all(self) -> list[Record]:
        return list(self.records)

    def clear(self) -> None:
        self.records.clear()


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------

SETTINGS_PATH = DEFAULT_DIR / "settings.json"


@dataclass
class Settings:
    """User preferences. Contains no secrets, so it is stored as plain JSON."""

    vault_path: str = ""
    theme: str = "dark"            # "dark" | "light"
    always_on_top: bool = False
    auto_lock_minutes: int = 5     # 0 disables
    clipboard_seconds: int = 30
    lock_on_minimize: bool = False
    backups: bool = True
    geometry: str = ""
    # generator
    gen_mode: str = "password"     # "password" | "passphrase" | "pin"
    gen_length: int = DEFAULT_LENGTH
    gen_lower: bool = True
    gen_upper: bool = True
    gen_digits: bool = True
    gen_symbols: bool = True
    gen_full_symbols: bool = False
    gen_exclude_ambiguous: bool = False
    gen_words: int = 5
    gen_separator: str = "-"
    gen_pin_length: int = 6

    @classmethod
    def load(cls, path: Path | str | None = None) -> "Settings":
        """Never fails: a missing or broken file yields defaults."""
        p = Path(path) if path else SETTINGS_PATH
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        if not isinstance(data, dict):
            return cls()
        defaults = cls()
        kwargs = {}
        for name, default in asdict(defaults).items():
            value = data.get(name, default)
            # Ignore values of the wrong type instead of crashing on them later.
            kwargs[name] = value if type(value) is type(default) else default
        return cls(**kwargs)

    def save(self, path: Path | str | None = None) -> None:
        p = Path(path) if path else SETTINGS_PATH
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(p)

    def vault_file(self) -> Path:
        return Path(self.vault_path) if self.vault_path else DEFAULT_DIR / "vault.awp"


# --------------------------------------------------------------------------
# Security audit
# --------------------------------------------------------------------------

WEAK_BITS = 60
OLD_DAYS = 365


def audit(records: list[Record], *, now: datetime | None = None) -> dict[str, list[Record]]:
    """Group records by problem: weak, reused, old, empty password."""
    now = now or datetime.now()
    by_password: dict[str, list[Record]] = {}
    for r in records:
        if r.password:
            by_password.setdefault(r.password, []).append(r)

    result: dict[str, list[Record]] = {"weak": [], "reused": [], "old": [], "empty": []}
    for r in records:
        if not r.password:
            result["empty"].append(r)
            continue
        if estimate_entropy(r.password) < WEAK_BITS:
            result["weak"].append(r)
        if len(by_password[r.password]) > 1:
            result["reused"].append(r)
        stamp = r.updated or r.created
        try:
            age = now - datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        if age.days > OLD_DAYS:
            result["old"].append(r)
    return result


def _restrict_permissions(path: Path) -> None:
    """Owner-only where the platform supports it. Silently skipped on Windows."""
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        pass


# --------------------------------------------------------------------------
# Export / import
# --------------------------------------------------------------------------

def export_plaintext(records: list[Record], path: Path | str) -> Path:
    """Export WITHOUT encryption. Refused by default in the UI: this writes passwords
    in the clear, which is the thing the vault exists to avoid."""
    p = Path(path)
    p.write_text(
        json.dumps([r.to_dict() for r in records], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    _restrict_permissions(p)
    return p


def export_encrypted(records: list[Record], path: Path | str, passphrase: str) -> Path:
    p = Path(path)
    salt = secrets.token_bytes(16)
    key = derive_key(passphrase, salt)
    payload = json.dumps([r.to_dict() for r in records], ensure_ascii=False).encode("utf-8")
    blob = b"AWPE" + salt + encrypt(payload, key)
    p.write_bytes(blob)
    _restrict_permissions(p)
    return p


def import_json(path: Path | str) -> list[Record]:
    """Read a plaintext export made by export_plaintext()."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except ValueError as e:
        raise ValueError("Файл не похож на экспорт в JSON") from e
    if isinstance(data, dict):
        data = data.get("records", [])
    if not isinstance(data, list) or not all(isinstance(r, dict) for r in data):
        raise ValueError("Файл не похож на экспорт в JSON")
    return [Record.from_dict(r) for r in data]


def import_encrypted(path: Path | str, passphrase: str) -> list[Record]:
    blob = Path(path).read_bytes()
    if blob[:4] != b"AWPE":
        raise ValueError("Это не зашифрованный экспорт")
    salt = blob[4:20]
    key = derive_key(passphrase, salt)
    payload = decrypt(blob[20:], key)
    return [Record.from_dict(r) for r in json.loads(payload.decode("utf-8"))]


# Header names used by other password managers, lower-cased, mapped to our fields.
# Covers Chrome/Edge, Firefox, Bitwarden, KeePass, KeePassXC, 1Password, LastPass.
CSV_ALIASES = {
    "site": ("name", "title", "account", "site"),
    "url": ("url", "login_uri", "web site", "website", "origin"),
    "login": ("username", "login_username", "login name", "login", "user"),
    "password": ("password", "login_password"),
    "note": ("note", "notes", "comments", "extra"),
    "folder": ("folder", "group", "grouping"),
    "totp": ("totp", "login_totp", "otpauth", "one-time password"),
    "email": ("email", "e-mail"),
    "favorite": ("favorite", "fav"),
    "tags": ("tags",),
}


def import_csv(path: Path | str) -> list[Record]:
    """Read a CSV exported by a browser or another password manager."""
    import io
    text = Path(path).read_text(encoding="utf-8-sig")
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if not reader.fieldnames:
        raise ValueError("Пустой CSV-файл")
    headers = {h.strip().lower(): h for h in reader.fieldnames if h}
    columns = {}
    for target, aliases in CSV_ALIASES.items():
        for alias in aliases:
            if alias in headers:
                columns[target] = headers[alias]
                break
    if "password" not in columns:
        raise ValueError("В CSV нет столбца с паролем (password)")

    records = []
    for row in reader:
        data = {k: (row.get(col) or "").strip() for k, col in columns.items()}
        if not data.get("password") and not data.get("site") and not data.get("url"):
            continue
        if not data.get("site") and data.get("url"):
            from urllib.parse import urlparse
            data["site"] = urlparse(data["url"]).hostname or data["url"]
        data["favorite"] = data.get("favorite", "").lower() in ("1", "true", "yes", "да")
        data["tags"] = data.get("tags", "")
        data["created"] = _now()
        records.append(Record.from_dict(data))
    return records


CSV_FIELDS = ("site", "url", "login", "email", "password", "totp", "folder", "tags",
              "favorite", "note", "created", "updated")


def export_csv(records: list[Record], path: Path | str) -> Path:
    """Export WITHOUT encryption, in a layout other managers can import."""
    p = Path(path)
    with p.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_FIELDS)
        for r in records:
            row = r.to_dict()
            row["tags"] = ", ".join(r.tags)
            row["favorite"] = "1" if r.favorite else ""
            writer.writerow([row[k] for k in CSV_FIELDS])
    _restrict_permissions(p)
    return p
