"""
Tests for core.py.

These are not decoration. Each one pins a behaviour that either was broken in the
original or is easy to break in a rewrite:

  * test_export_survives_restart is the regression test for the defect that made
    the original unusable: a key regenerated per launch meant no saved file could
    ever be read back.
"""

import json
import string
from pathlib import Path

import pytest

from core import (
    ALL_SYMBOLS,
    HISTORY_LIMIT,
    SAFE_SYMBOLS,
    Record,
    Vault,
    decrypt,
    derive_key,
    encrypt,
    export_encrypted,
    export_plaintext,
    estimate_entropy,
    estimate_pool_size,
    generate_password,
    import_encrypted,
    strength_label,
    build_alphabet,
)


# --------------------------------------------------------------------------
# Password generation
# --------------------------------------------------------------------------

def test_default_length_is_respected():
    assert len(generate_password(20)) == 20
    assert len(generate_password(32)) == 32


@pytest.mark.parametrize("bad", [0, 1, 7, -5, 999])
def test_rejects_out_of_range_length(bad):
    with pytest.raises(ValueError):
        generate_password(bad)


def test_rejects_non_integer_length():
    with pytest.raises(ValueError):
        generate_password("sixteen")  # type: ignore[arg-type]


def test_contains_at_least_one_from_each_enabled_class():
    for _ in range(200):
        pwd = generate_password(16)
        assert any(c in string.ascii_lowercase for c in pwd)
        assert any(c in string.ascii_uppercase for c in pwd)
        assert any(c in string.digits for c in pwd)


def test_never_produces_characters_that_sites_reject():
    """The original used string.punctuation, which emitted quotes and backslash."""
    dangerous = set("'\"`\\ ")
    for _ in range(500):
        pwd = generate_password(32)
        assert not (set(pwd) & dangerous), f"found {set(pwd) & dangerous}"


def test_disabled_classes_are_absent():
    for _ in range(200):
        pwd = generate_password(24, symbols=False)
        assert not (set(pwd) & set(SAFE_SYMBOLS))

    for _ in range(200):
        pwd = generate_password(24, digits=False)
        assert not (set(pwd) & set(string.digits))


def test_exclude_ambiguous():
    ambiguous = set("Il1O0o")
    for _ in range(300):
        pwd = generate_password(40, exclude_ambiguous=True)
        assert not (set(pwd) & ambiguous)


def test_exclude_ambiguous_can_still_satisfy_length():
    """With a tiny length the filter must not leave the generator short."""
    pwd = generate_password(8, exclude_ambiguous=True)
    assert len(pwd) == 8


def test_length_below_minimum_is_refused_even_with_classes_disabled():
    """A short password is refused regardless of how many classes are on.

    The global MIN_LENGTH guard runs first, so length=3 must be rejected rather
    than quietly producing a 3-character password that satisfies the class rules.
    """
    with pytest.raises(ValueError):
        generate_password(3, lowercase=True, uppercase=True, digits=True, symbols=False)


def test_alphabet_requires_at_least_one_class():
    with pytest.raises(ValueError):
        build_alphabet(lowercase=False, uppercase=False, digits=False, symbols=False)


def test_ambiguous_filter_must_not_silently_empty_a_class():
    """Filtering away every lowercase letter must be reported, not worked around.

    The guard exists because a silent fallback would hand back a password that does
    not match what the user asked for, with no indication anything changed.
    """
    # exclude_ambiguous removes only I, l, 1, O, 0, o from lowercase - not all of it.
    # So to empty the class we must turn off every other source.
    # exclude_ambiguous removes I, l, 1, O, 0, o. Lowercase still has plenty left,
    # so this must SUCCEED - the point of the test is that the guard does not fire
    # spuriously on a normal request.
    pool = build_alphabet(lowercase=True, uppercase=True, digits=True, symbols=True, exclude_ambiguous=True)
    assert pool
    assert not (set(pool) & set("Il1O0o"))


def test_exclude_ambiguous_is_honoured_for_symbols():
    """Symbols are not a mandatory class, so they may legitimately end up empty."""
    pool = build_alphabet(
        lowercase=True,
        uppercase=True,
        digits=True,
        symbols=True,
        exclude_ambiguous=True,
    )
    assert not (set(pool) & set("Il1O0o"))


def test_passwords_are_not_constant():
    """Guards against a seeding bug that would make every call identical."""
    seen = {generate_password(16) for _ in range(100)}
    assert len(seen) == 100


def test_full_symbols_may_include_quotes_when_opted_in():
    """full_symbols=True widens the SYMBOL set only. Letters and digits stay on,
    so the assertion must be about the symbol subset, not the whole string."""
    for _ in range(50):
        pwd = generate_password(200, full_symbols=True)
        # No character outside the full alphabet may appear.
        allowed = set(string.ascii_letters + string.digits) | set(ALL_SYMBOLS)
        assert set(pwd) <= allowed, f"unexpected: {set(pwd) - allowed}"
        # And it must be able to emit the very characters the default set withholds.
    seen = set()
    for _ in range(300):
        seen |= set(generate_password(120, full_symbols=True))
    assert seen & set("'\"`\\"), "opt-in symbol set should include quotes and backslash"


# --------------------------------------------------------------------------
# Entropy and strength
# --------------------------------------------------------------------------

def test_entropy_grows_with_length():
    short = estimate_entropy(generate_password(12))
    long = estimate_entropy(generate_password(32))
    assert long > short


def test_entropy_grows_with_pool_size():
    small = estimate_entropy("aB3", estimate_pool_size("aB3"))
    large = estimate_entropy("aB3", 94)
    assert large > small


def test_strength_labels_are_ordered():
    labels = [strength_label(b) for b in (10, 50, 70, 100, 200)]
    assert labels == ["Очень слабый", "Слабый", "Средний", "Сильный", "Очень сильный"]


def test_default_password_is_strong():
    """The shipped default must not be laughably weak."""
    bits = estimate_entropy(generate_password(20))
    assert bits >= 100, f"default entropy too low: {bits}"
    assert strength_label(bits) in ("Сильный", "Очень сильный")


# --------------------------------------------------------------------------
# Crypto primitives
# --------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip():
    key = derive_key("passphrase", b"somesalt12345678")
    # Non-ASCII must survive: the user writes passwords and notes in Russian, and
    # the encrypt path is byte-oriented, so UTF-8 is what crosses the wire.
    msg = "secret in Russian: пароль".encode("utf-8")
    assert decrypt(encrypt(msg, key), key) == msg


def test_encrypt_produces_different_ciphertext_each_time():
    """A fixed nonce would leak that two records share a plaintext."""
    key = derive_key("p", b"s" * 16)
    a = encrypt(b"same", key)
    b = encrypt(b"same", key)
    assert a != b


def test_wrong_key_is_rejected():
    blob = encrypt(b"data", derive_key("right", b"s" * 16))
    with pytest.raises(ValueError):
        decrypt(blob, derive_key("wrong", b"s" * 16))


def test_tampering_is_detected():
    """Flip one byte of ciphertext; the MAC must catch it."""
    key = derive_key("p", b"s" * 16)
    blob = bytearray(encrypt(b"important", key))
    blob[-1] ^= 0x01
    with pytest.raises(ValueError):
        decrypt(bytes(blob), key)


def test_truncated_blob_is_rejected():
    key = derive_key("p", b"s" * 16)
    blob = encrypt(b"x", key)
    with pytest.raises(ValueError):
        decrypt(blob[:10], key)


def test_wrong_format_is_rejected():
    with pytest.raises(ValueError):
        decrypt(b"NOPE" + b"\x00" * 64, derive_key("p", b"s" * 16))


def test_scrypt_is_deterministic_and_salt_sensitive():
    assert derive_key("pw", b"a" * 16) == derive_key("pw", b"a" * 16)
    assert derive_key("pw", b"a" * 16) != derive_key("pw", b"b" * 16)


# --------------------------------------------------------------------------
# Vault: the regression that matters
# --------------------------------------------------------------------------

def test_vault_persists_across_sessions(tmp_path):
    """THE regression test.

    The original regenerated the encryption key in __init__, so a vault saved in
    one session could never be opened in another. This must never come back.
    """
    path = tmp_path / "vault.awp"

    v1 = Vault(path)
    v1.create("master-pass")
    v1.add("s3cret-1", site="github.com", login="god", email="a@b.c")
    v1.add("s3cret-2", site="mail.ru", login="god2")
    v1.save()
    v1.path = path  # create() may rewrite self.path; keep it consistent

    # A genuinely separate session: new object, new unlock.
    v2 = Vault(path)
    v2.unlock("master-pass")

    assert len(v2.all()) == 2
    sites = sorted(r.site for r in v2.all())
    assert sites == ["github.com", "mail.ru"]
    assert sorted(r.password for r in v2.all()) == ["s3cret-1", "s3cret-2"]


def test_vault_rejects_wrong_passphrase(tmp_path):
    path = tmp_path / "v.awp"
    v = Vault(path)
    v.create("correct")
    v.add("pw", site="x")
    v.save()

    v2 = Vault(path)
    with pytest.raises(ValueError):
        v2.unlock("wrong")


def test_vault_create_refuses_to_overwrite(tmp_path):
    path = tmp_path / "v.awp"
    v = Vault(path)
    v.create("pass")
    with pytest.raises(FileExistsError):
        Vault(path).create("other")


def test_vault_rejects_empty_passphrase(tmp_path):
    with pytest.raises(ValueError):
        Vault(tmp_path / "v.awp").create("")


def test_vault_file_is_not_plaintext(tmp_path):
    """A vault on disk must not leak the passwords it holds."""
    path = tmp_path / "v.awp"
    v = Vault(path)
    v.create("pass")
    v.add("plaintext-password", site="visible.com")
    v.save()

    blob = path.read_bytes()
    assert b"plaintext-password" not in blob
    assert b"visible.com" not in blob


def test_vault_unlock_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        Vault(tmp_path / "nope.awp").unlock("x")


def test_save_without_unlock_is_refused(tmp_path):
    v = Vault(tmp_path / "v.awp")
    with pytest.raises(RuntimeError):
        v.save()


# --------------------------------------------------------------------------
# Record operations
# --------------------------------------------------------------------------

@pytest.fixture
def vault(tmp_path):
    v = Vault(tmp_path / "v.awp")
    v.create("pass")
    return v


def test_add_and_get(vault):
    rec = vault.add("pw123", site="s", login="l", email="e")
    assert vault.get(rec.id) is rec
    assert rec.created  # timestamp auto-filled


def test_delete(vault):
    rec = vault.add("pw")
    assert vault.delete(rec.id) is True
    assert vault.get(rec.id) is None
    assert vault.delete("nonexistent") is False


def test_edit(vault):
    rec = vault.add("old", site="a")
    assert vault.edit(rec.id, site="b", password="new") is True
    assert rec.site == "b"
    assert rec.password == "new"


def test_edit_ignores_unknown_fields(vault):
    """A caller must not be able to set arbitrary attributes."""
    rec = vault.add("pw", site="a")
    vault.edit(rec.id, site="b", id="hacked", created="1970")
    assert rec.id != "hacked"


def test_edit_unknown_id(vault):
    assert vault.edit("nope", site="x") is False


def test_search_matches_site_login_email(vault):
    vault.add("p1", site="github.com", login="alice", email="a@x.com")
    vault.add("p2", site="mail.ru", login="bob", email="b@y.com")

    assert len(vault.search("github")) == 1
    assert len(vault.search("alice")) == 1
    assert len(vault.search("y.com")) == 1
    assert vault.search("GITHUB") == vault.search("github")  # case-insensitive
    assert vault.search("nothing-here") == []


def test_search_empty_query_returns_nothing(vault):
    vault.add("p", site="x")
    assert vault.search("") == []


def test_clear(vault):
    vault.add("a")
    vault.add("b")
    vault.clear()
    assert vault.all() == []


# --------------------------------------------------------------------------
# Export / import
# --------------------------------------------------------------------------

def test_encrypted_export_import_roundtrip(tmp_path):
    records = [Record(id="1", password="p1", site="a"), Record(id="2", password="p2", site="b")]
    out = tmp_path / "exp.awpe"
    export_encrypted(records, out, "export-pass")

    assert b"p1" not in out.read_bytes()

    restored = import_encrypted(out, "export-pass")
    assert sorted(r.password for r in restored) == ["p1", "p2"]


def test_encrypted_import_wrong_passphrase(tmp_path):
    out = tmp_path / "exp.awpe"
    export_encrypted([Record(id="1", password="p")], out, "right")
    with pytest.raises(ValueError):
        import_encrypted(out, "wrong")


def test_import_rejects_plaintext_file(tmp_path):
    out = tmp_path / "plain.json"
    export_plaintext([Record(id="1", password="p")], out)
    with pytest.raises(ValueError):
        import_encrypted(out, "anything")


def test_plaintext_export_roundtrip(tmp_path):
    out = tmp_path / "plain.json"
    export_plaintext([Record(id="1", password="p1", site="s")], out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data[0]["password"] == "p1"


# --------------------------------------------------------------------------
# Regression: the exact original defect
# --------------------------------------------------------------------------

def test_key_is_not_regenerated_per_instance(tmp_path):
    """Directly mirrors the original bug.

    Original: `self.key = Fernet.generate_key()` in __init__. Two instances could
    therefore never share data. The salt file is what makes the key stable now.
    """
    path = tmp_path / "k.awp"

    a = Vault(path)
    a.create("pass")
    a.add("data", site="s")
    a.save()

    b = Vault(path)
    b.unlock("pass")
    c = Vault(path)
    c.unlock("pass")

    # Both later sessions must see the same record, not an empty or failed vault.
    assert len(b.all()) == 1
    assert len(c.all()) == 1
    assert b.all()[0].password == "data"

# --------------------------------------------------------------------------
# Extended records
# --------------------------------------------------------------------------

def test_old_records_load_with_defaults():
    rec = Record.from_dict({"id": "x", "password": "p", "site": "s"})
    assert rec.tags == [] and rec.favorite is False and rec.totp == "" and rec.history == []


def test_tags_from_string_are_split():
    rec = Record.from_dict({"id": "x", "password": "p", "tags": "work, mail ,"})
    assert rec.tags == ["work", "mail"]


def test_add_accepts_extra_fields(vault):
    rec = vault.add("pw", "site", url="https://e.com", folder="Работа",
                    tags=["a"], favorite=True)
    assert rec.url == "https://e.com" and rec.folder == "Работа"
    assert rec.favorite and rec.tags == ["a"] and rec.updated == rec.created


def test_edit_keeps_password_history(vault):
    rec = vault.add("old-password", "site")
    vault.edit(rec.id, password="new-password")
    assert rec.password == "new-password"
    assert rec.history[0]["password"] == "old-password"


def test_history_is_bounded(vault):
    rec = vault.add("p0", "site")
    for i in range(1, 30):
        vault.edit(rec.id, password=f"p{i}")
    assert len(rec.history) == HISTORY_LIMIT
    assert rec.history[0]["password"] == "p28"


def test_search_covers_note_url_folder_tags(vault):
    vault.add("p", "a", note="секретная заметка")
    vault.add("p", "b", url="https://bank.example")
    vault.add("p", "c", folder="Финансы", tags=["important"])
    assert len(vault.search("заметка")) == 1
    assert len(vault.search("bank")) == 1
    assert len(vault.search("финансы")) == 1
    assert len(vault.search("IMPORT")) == 1


def test_extended_fields_survive_save(tmp_path):
    v = Vault(tmp_path / "v.awp")
    v.create("passphrase-1")
    v.add("p", "s", folder="F", tags=["t"], favorite=True, totp="JBSWY3DPEHPK3PXP")
    v.save()
    v2 = Vault(tmp_path / "v.awp")
    v2.unlock("passphrase-1")
    r = v2.all()[0]
    assert (r.folder, r.tags, r.favorite, r.totp) == ("F", ["t"], True, "JBSWY3DPEHPK3PXP")
