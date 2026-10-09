"""
Smoke tests for the interface. They open a real window, so they need a display;
CI runs them under Xvfb. Without a display or tkinter they are skipped, and the
core tests still run.
"""

import os
import sys

import pytest

tk = pytest.importorskip("tkinter")

if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
    pytest.skip("нет дисплея", allow_module_level=True)

import core  # noqa: E402
import ui  # noqa: E402

MASTER = "correct horse battery"


@pytest.fixture
def app(tmp_path):
    root = tk.Tk()
    root.withdraw()
    settings = core.Settings(vault_path=str(tmp_path / "v.awp"))
    application = ui.App(root, settings, tmp_path / "settings.json")
    yield application
    root.destroy()


def unlock(app, master=MASTER):
    lock = app.screens["lock"]
    lock.var_master.set(master)
    lock.var_confirm.set(master)
    lock.submit()


def test_starts_on_lock_screen_in_create_mode(app):
    assert app.current == "lock"
    assert app.screens["lock"].creating


def test_create_refuses_mismatch_and_short(app):
    lock = app.screens["lock"]
    lock.var_master.set("short")
    lock.submit()
    assert app.vault is None
    lock.var_master.set(MASTER)
    lock.var_confirm.set(MASTER + "x")
    lock.submit()
    assert app.vault is None


def test_create_add_lock_unlock(app):
    unlock(app)
    assert app.current == "list" and app.vault is not None
    app.show("edit")
    edit = app.screens["edit"]
    assert edit.vars["password"].get(), "new record gets a generated password"
    edit.vars["site"].set("GitHub")
    edit.vars["login"].set("me")
    edit.vars["totp"].set("jbsw y3dp ehpk 3pxp")
    edit.save()
    assert app.current == "list"
    [rec] = app.vault.all()
    assert rec.totp == "JBSWY3DPEHPK3PXP"

    app.lock()
    assert app.current == "lock" and app.vault is None
    lock = app.screens["lock"]
    assert not lock.creating
    lock.var_master.set("wrong password")
    lock.submit()
    assert app.vault is None and lock.lbl_error.cget("text")
    unlock(app)
    assert app.vault.all()[0].site == "GitHub"


def test_edit_requires_name_and_valid_totp(app):
    unlock(app)
    app.show("edit")
    edit = app.screens["edit"]
    edit.save()
    assert app.current == "edit" and not app.vault.all()
    edit.vars["site"].set("x")
    edit.vars["totp"].set("not base32 !!")
    edit.save()
    assert app.current == "edit" and not app.vault.all()


def test_search_and_folders(app):
    unlock(app)
    app.vault.add("p1", "Почта", folder="Личное")
    app.vault.add("p2", "Банк", folder="Финансы", favorite=True)
    app.vault.add("p3", "Форум")
    screen = app.screens["list"]
    screen.refresh()
    assert len(screen.tree.get_children()) == 3
    assert screen.tree.get_children()[0] == app.vault.all()[1].id, "favourites first"
    screen.var_search.set("почт")
    assert len(screen.tree.get_children()) == 1
    screen.var_search.set("")
    screen.var_folder.set("Финансы")
    screen.refresh()
    assert len(screen.tree.get_children()) == 1
    screen.var_folder.set("Все папки")
    screen.var_fav.set(True)
    screen.refresh()
    assert len(screen.tree.get_children()) == 1


def test_generator_modes(app):
    app.show("generator", back="lock")
    gen = app.screens["generator"]
    for mode in ("password", "passphrase", "pin"):
        gen.var_mode.set(mode)
        gen.on_mode()
        assert gen.password
    assert gen.password.isdigit()
    assert app.settings.gen_mode == "pin"


def test_copy_and_clear_only_our_text(app):
    app.copy("secret-value", "Пароль")
    assert app.root.clipboard_get() == "secret-value"
    app.root.clipboard_clear()
    app.root.clipboard_append("user text")
    app._clear_clipboard()
    assert app.root.clipboard_get() == "user text"


def test_auto_lock(app):
    unlock(app)
    app.settings.auto_lock_minutes = 1
    app._last_activity -= 120
    app._watch_idle()
    assert app.vault is None and app.current == "lock"


def test_theme_switch_keeps_screen(app):
    unlock(app)
    app.show("settings")
    app.set_theme("light")
    assert app.current == "settings" and app.theme.name == "light"


def test_all_screens_open(app):
    unlock(app)
    app.vault.add("abc12345", "weak")
    for name in ("list", "edit", "generator", "settings", "audit", "list"):
        app.show(name)
        app.root.update_idletasks()
    assert app.screens["audit"].tree.get_children()


@pytest.mark.parametrize("keysym, keycode, expected", [
    ("f", 41, "f"),
    ("F", 41, "f"),
    ("Cyrillic_a", 41, "f" if sys.platform.startswith("linux") else ""),
])
def test_latin_key(keysym, keycode, expected):
    class Event:
        pass
    e = Event()
    e.keysym, e.keycode = keysym, keycode
    if sys.platform == "win32" and keysym.startswith("Cyrillic"):
        e.keycode, expected = 70, "f"
    assert ui.latin_key(e) == expected
