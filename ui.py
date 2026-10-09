"""
ui.py - tkinter interface for the password vault.

One small window instead of a wall of buttons. It is meant to stay open all day
in a corner of the screen, so everything is organised as screens that replace
each other inside the same window:

    lock      -> master password; creates the vault on first run
    list      -> search, folders, favourites, a card with copy buttons and 2FA code
    edit      -> one record
    generator -> passwords, passphrases, PINs
    audit     -> weak, reused and old passwords
    settings  -> appearance, security, import/export, master password

Rules carried over from the previous interface, because they protect the data:

  * Nothing is saved without an explicit action; generating does not save.
  * Every irreversible action asks first.
  * The clipboard is cleared after a delay - and only if it still holds what we
    put there, so the user's own clipboard is never wiped.
  * The vault locks itself after a period of inactivity.
"""

from __future__ import annotations

import sys
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from core import (
    MAX_LENGTH,
    MIN_LENGTH,
    PASSPHRASE_MAX_WORDS,
    PASSPHRASE_MIN_WORDS,
    Record,
    Settings,
    Vault,
    __version__,
    audit,
    estimate_entropy,
    export_csv,
    export_encrypted,
    generate_passphrase,
    generate_password,
    generate_pin,
    import_csv,
    import_encrypted,
    import_json,
    normalize_totp_secret,
    passphrase_entropy,
    strength_label,
    totp,
    totp_remaining,
)
from theme import PlaceholderEntry, ScrollFrame, StrengthBar, Theme, Toggle, enable_hidpi

APP_TITLE = "Генератор паролей"
DEFAULT_GEOMETRY = "380x580"
MASK = "•" * 10


class App:
    def __init__(self, root: tk.Tk, settings: Settings | None = None,
                 settings_path: Path | None = None) -> None:
        self.root = root
        self.settings_path = settings_path
        self.settings = settings or Settings.load(settings_path)
        self.vault: Vault | None = None
        self._clipboard_job: str | None = None
        self._clipboard_text: str | None = None
        self._toast_job: str | None = None

        root.title(APP_TITLE)
        root.geometry(self.settings.geometry or DEFAULT_GEOMETRY)
        root.minsize(340, 460)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.attributes("-topmost", self.settings.always_on_top)
        self._set_icon()

        self.theme = Theme(root, self.settings.theme)
        # Status first, so a crowded screen squeezes its own content, not the status.
        self.status = ttk.Label(root, style="Muted.TLabel", anchor="w", padding=(12, 3, 12, 6))
        self.status.pack(fill="x", side="bottom")
        self.body = ttk.Frame(root)
        self.body.pack(fill="both", expand=True)

        self.screens: dict[str, Screen] = {}
        self.current = ""
        self._build_screens()
        self.show("lock")

        self._last_activity = time.monotonic()
        for event in ("<KeyPress>", "<ButtonPress>", "<Motion>"):
            root.bind_all(event, self._touch, add="+")
        root.bind("<Control-KeyPress>", self._on_ctrl_key)
        root.bind("<Escape>", lambda _e: self.screens[self.current].on_escape())
        root.bind("<Unmap>", self._on_unmap)
        self._watch_idle()

    # -- screens ---------------------------------------------------------

    def _build_screens(self) -> None:
        for screen in self.screens.values():
            screen.destroy()
        self.screens = {cls.name: cls(self.body, self) for cls in SCREENS}

    def show(self, name: str, **kwargs) -> None:
        if self.current in self.screens:
            self.screens[self.current].pack_forget()
            self.screens[self.current].on_hide()
        self.current = name
        screen = self.screens[name]
        screen.pack(fill="both", expand=True)
        screen.on_show(**kwargs)

    def set_theme(self, name: str) -> None:
        self.settings.theme = name
        self.save_settings()
        self.theme.apply(name)
        current = self.current
        self.current = ""
        self._build_screens()
        self.show(current)

    # -- vault lifecycle -------------------------------------------------

    def opened(self, vault: Vault) -> None:
        vault.backups = self.settings.backups
        self.vault = vault
        self.settings.vault_path = str(vault.path)
        self.save_settings()
        self.show("list")

    def lock(self, reason: str = "Хранилище заблокировано") -> None:
        if self.vault is None:
            return
        self.vault = None
        # A password copied from the vault should not outlive the unlocked session.
        if self._clipboard_text is not None:
            self._clear_clipboard(force=True)
        for dialog in self.root.winfo_children():
            if isinstance(dialog, tk.Toplevel):
                dialog.destroy()
        self.show("lock")
        self.toast(reason)

    # -- activity, auto-lock, shortcuts ----------------------------------

    def _touch(self, _event=None) -> None:
        self._last_activity = time.monotonic()

    def _watch_idle(self) -> None:
        minutes = self.settings.auto_lock_minutes
        if self.vault is not None and minutes > 0:
            if time.monotonic() - self._last_activity > minutes * 60:
                self.lock(f"Заблокировано после {minutes} мин без действий")
        self.root.after(5000, self._watch_idle)

    def _on_unmap(self, event: tk.Event) -> None:
        if (event.widget is self.root and self.settings.lock_on_minimize
                and self.root.state() == "iconic"):
            self.lock()

    def _on_ctrl_key(self, event: tk.Event) -> str | None:
        key = latin_key(event)
        if not key:
            return None
        if key == "l" and self.vault is not None:
            self.lock()
            return "break"
        screen = self.screens.get(self.current)
        if screen is not None and screen.shortcut(key, event):
            return "break"
        return None

    def save_vault(self) -> bool:
        """Persist the vault; report failure instead of losing the change silently."""
        if self.vault is None:
            return False
        try:
            self.vault.save()
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Не удалось сохранить: {e}", parent=self.root)
            return False
        return True

    def save_settings(self) -> None:
        try:
            self.settings.save(self.settings_path)
        except OSError:
            pass  # preferences are a convenience; never block the user over them

    # -- feedback --------------------------------------------------------

    def toast(self, message: str, kind: str = "") -> None:
        style = {"error": "Danger.TLabel", "ok": "Ok.TLabel"}.get(kind, "Muted.TLabel")
        self.status.configure(text=message, style=style)
        if self._toast_job:
            self.root.after_cancel(self._toast_job)
        self._toast_job = self.root.after(4000, lambda: self.status.configure(text=""))

    def copy(self, text: str, what: str = "Пароль") -> None:
        if not text:
            self.toast(f"{what}: пусто", "error")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._clipboard_text = text
        seconds = self.settings.clipboard_seconds
        if self._clipboard_job:
            self.root.after_cancel(self._clipboard_job)
            self._clipboard_job = None
        if seconds > 0:
            self._clipboard_job = self.root.after(seconds * 1000, self._clear_clipboard)
            self.toast(f"{what} скопирован · очистка через {seconds} с", "ok")
        else:
            self.toast(f"{what} скопирован", "ok")

    def _clear_clipboard(self, force: bool = False) -> None:
        self._clipboard_job = None
        try:
            current = self.root.clipboard_get()
        except tk.TclError:
            current = None
        # Do not wipe something the user copied after us.
        if force or current == self._clipboard_text:
            try:
                self.root.clipboard_clear()
            except tk.TclError:
                pass
            if not force:
                self.toast("Буфер обмена очищен")
        self._clipboard_text = None

    # -- window ----------------------------------------------------------

    def set_topmost(self, on: bool) -> None:
        self.settings.always_on_top = on
        self.root.attributes("-topmost", on)
        self.save_settings()

    def _set_icon(self) -> None:
        base = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
        icon = base / "build_assets" / "icon.png"
        if icon.exists():
            try:
                self._icon = tk.PhotoImage(file=str(icon))
                self.root.iconphoto(True, self._icon)
            except tk.TclError:
                pass

    def on_close(self) -> None:
        if self._clipboard_job:
            self.root.after_cancel(self._clipboard_job)
        if self._clipboard_text is not None:
            self._clear_clipboard(force=True)
        if self.root.state() == "normal":
            self.settings.geometry = self.root.geometry()
        self.save_settings()
        self.root.destroy()


# ----------------------------------------------------------------------
# Screens
# ----------------------------------------------------------------------

class Screen(ttk.Frame):
    name = ""

    def __init__(self, master: tk.Misc, app: App) -> None:
        super().__init__(master, padding=(12, 10, 12, 0))
        self.app = app
        self.theme = app.theme
        self.build()

    def build(self) -> None:
        raise NotImplementedError

    def on_show(self, **kwargs) -> None:
        pass

    def on_hide(self) -> None:
        pass

    def shortcut(self, key: str, event: tk.Event) -> bool:
        """Handle Ctrl+key; return True when consumed."""
        return False

    def on_escape(self) -> None:
        pass

    def header(self, title: str, back: str | None = "list") -> ttk.Frame:
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 8))
        if back:
            ttk.Button(bar, text="←", style="Icon.TButton", width=2,
                       command=lambda: self.app.show(back)).pack(side="left")
        ttk.Label(bar, text=title, style="Title.TLabel").pack(side="left", padx=(4, 0))
        return bar


class LockScreen(Screen):
    name = "lock"

    def build(self) -> None:
        self.var_master = tk.StringVar()
        self.var_confirm = tk.StringVar()
        self.var_show = tk.BooleanVar(value=False)

        center = ttk.Frame(self)
        center.place(relx=0.5, rely=0.42, anchor="center", relwidth=1.0)
        inner = ttk.Frame(center, padding=(16, 0))
        inner.pack(fill="x")

        ttk.Label(inner, text="●●●", foreground=self.theme.c["accent"],
                  font=(self.theme.font[0], 20, "bold")).pack()
        ttk.Label(inner, text=APP_TITLE, style="Title.TLabel").pack(pady=(4, 0))
        self.lbl_sub = ttk.Label(inner, style="Muted.TLabel", justify="center")
        self.lbl_sub.pack(pady=(2, 16))

        self.entry = ttk.Entry(inner, textvariable=self.var_master, show="•")
        self.entry.pack(fill="x")
        self.entry.bind("<Return>", lambda _e: self.submit())
        self.confirm_row = ttk.Frame(inner)
        self.entry_confirm = ttk.Entry(self.confirm_row, textvariable=self.var_confirm, show="•")
        self.entry_confirm.pack(fill="x", pady=(6, 0))
        self.entry_confirm.bind("<Return>", lambda _e: self.submit())
        ttk.Label(self.confirm_row, style="Muted.TLabel", wraplength=300, justify="left",
                  text="Мастер-пароль нигде не хранится. Забудете — восстановить "
                       "пароли будет нельзя.").pack(anchor="w", pady=(6, 0))

        self.opts = ttk.Frame(inner)
        self.opts.pack(fill="x", pady=(6, 0))
        ttk.Checkbutton(self.opts, text="Показать", variable=self.var_show,
                        command=self._toggle_show).pack(side="left")

        self.lbl_error = ttk.Label(inner, style="Danger.TLabel", wraplength=320)
        self.lbl_error.pack(fill="x", pady=(6, 0))
        self.btn = ttk.Button(inner, style="Accent.TButton", command=self.submit)
        self.btn.pack(fill="x", pady=(4, 0))

        bottom = ttk.Frame(self)
        bottom.pack(side="bottom", fill="x", pady=(0, 4))
        self.lbl_path = ttk.Label(bottom, style="Muted.TLabel", anchor="center")
        self.lbl_path.pack(fill="x")
        links = ttk.Frame(bottom)
        links.pack()
        ttk.Button(links, text="Другой файл…", style="Link.TButton",
                   command=self.choose_file).pack(side="left")
        ttk.Button(links, text="Генератор без входа", style="Link.TButton",
                   command=lambda: self.app.show("generator", back="lock")).pack(side="left")

    def path(self) -> Path:
        return self.app.settings.vault_file()

    def on_show(self, **_kwargs) -> None:
        self.var_master.set("")
        self.var_confirm.set("")
        self.lbl_error.configure(text="")
        self.creating = not self.path().exists()
        if self.creating:
            self.lbl_sub.configure(text="Придумайте мастер-пароль\nдля нового хранилища")
            self.confirm_row.pack(fill="x", after=self.entry)
            self.btn.configure(text="Создать хранилище")
        else:
            self.lbl_sub.configure(text="Введите мастер-пароль")
            self.confirm_row.pack_forget()
            self.btn.configure(text="Открыть")
        self._show_path()
        self.after(50, self.entry.focus_set)

    def _show_path(self) -> None:
        text = str(self.path())
        if len(text) > 48:
            text = "…" + text[-47:]
        self.lbl_path.configure(text=text)

    def _toggle_show(self) -> None:
        show = "" if self.var_show.get() else "•"
        self.entry.configure(show=show)
        self.entry_confirm.configure(show=show)

    def choose_file(self) -> None:
        # One dialog for both cases: pick an existing vault, or type a new name.
        chosen = filedialog.asksaveasfilename(
            parent=self, title="Выберите файл хранилища или введите новое имя",
            initialdir=str(self.path().parent), initialfile=self.path().name,
            defaultextension=".awp", confirmoverwrite=False,
            filetypes=[("Хранилище", "*.awp"), ("Все файлы", "*.*")],
        )
        if chosen:
            self.app.settings.vault_path = chosen
            self.app.save_settings()
            self.on_show()

    def submit(self) -> None:
        master = self.var_master.get()
        if not master:
            self.lbl_error.configure(text="Введите мастер-пароль")
            return
        if self.creating:
            error = self._check_new(master)
            if error:
                self.lbl_error.configure(text=error)
                return
        self.lbl_error.configure(text="")
        self.app.root.configure(cursor="watch")
        self.update_idletasks()
        try:
            vault = Vault(self.path())
            if self.creating:
                vault.create(master)
            else:
                vault.unlock(master)
        except (ValueError, OSError) as e:
            self.lbl_error.configure(text=str(e))
            self.var_master.set("")
            return
        finally:
            self.app.root.configure(cursor="")
        self.var_master.set("")
        self.var_confirm.set("")
        self.app.opened(vault)
        self.app.toast("Хранилище создано" if self.creating else "Хранилище открыто", "ok")

    def _check_new(self, master: str) -> str:
        if master != master.strip():
            return "Уберите пробелы в начале или в конце"
        if len(master) < 8:
            return "Слишком коротко: нужно хотя бы 8 символов"
        if master != self.var_confirm.get():
            return "Пароли не совпадают"
        return ""


class ListScreen(Screen):
    name = "list"

    def build(self) -> None:
        self.var_search = tk.StringVar()
        self.var_folder = tk.StringVar(value="Все папки")
        self.var_fav = tk.BooleanVar(value=False)
        self.revealed = False
        self.selected: Record | None = None
        self._tick_job: str | None = None

        top = ttk.Frame(self)
        top.pack(fill="x")
        # Toolbar first: when the window is narrow the search box gives way, not the icons.
        self.toolbar = ttk.Frame(top)
        self.toolbar.pack(side="right", padx=(4, 0))
        self.search = PlaceholderEntry(top, self.theme, "Поиск  (Ctrl+F)", self.var_search)
        self.search.pack(side="left", fill="x", expand=True)
        self.var_search.trace_add("write", lambda *_: self.refresh())
        self.search.bind("<Down>", lambda _e: self._focus_list())
        self.search.bind("<Return>", lambda _e: self._enter_from_search())
        self.search.bind("<Escape>", lambda _e: self.var_search.set(""))
        self.search.bind("<Control-KeyPress>", self._search_ctrl)
        self.add_tool("＋", "Новая запись (Ctrl+N)", lambda: self.app.show("edit"))
        self.add_tool("⚄", "Генератор (Ctrl+G)", lambda: self.app.show("generator"))
        self.btn_pin = self.add_tool("▣", "Поверх всех окон", self.toggle_pin)
        self.add_tool("⚙", "Настройки", lambda: self.app.show("settings"))
        self.add_tool("⏻", "Заблокировать (Ctrl+L)", self.app.lock)
        self._sync_pin()

        filt = ttk.Frame(self)
        filt.pack(fill="x", pady=(8, 6))
        fav = Toggle(filt, self.var_fav, "★", "☆", command=self.refresh)
        fav.pack(side="left")
        Tooltip(fav, "Только избранное", self.theme)
        self.folder_box = ttk.Combobox(filt, textvariable=self.var_folder, state="readonly",
                                       width=16)
        self.folder_box.pack(side="left", padx=(4, 0))
        self.folder_box.bind("<<ComboboxSelected>>", lambda _e: self.refresh())
        self.lbl_count = ttk.Label(filt, style="Muted.TLabel")
        self.lbl_count.pack(side="right")
        self.btn_audit = ttk.Button(filt, style="Warn.TButton",
                                    command=lambda: self.app.show("audit"))
        Tooltip(self.btn_audit, "Слабые, повторяющиеся и старые пароли", self.theme)

        # Packed before the list so the card keeps its height and the list shrinks.
        self.bottom = ttk.Frame(self)
        self.bottom.pack(side="bottom", fill="x")
        list_frame = ttk.Frame(self, style="Card.TFrame")
        list_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(list_frame, columns=("title", "login"), show="",
                                 selectmode="browse", height=4)
        self.tree.column("title", width=170, stretch=True)
        self.tree.column("login", width=130, stretch=True)
        self.tree.tag_configure("muted", foreground=self.theme.c["muted"])
        sb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._on_select())
        self.tree.bind("<Double-1>", lambda _e: self.copy_password())
        self.tree.bind("<Return>", lambda _e: self.copy_password())
        self.tree.bind("<Key>", self._type_to_search)
        self.tree.bind("<Delete>", lambda _e: self.delete_selected())
        self.tree.bind("<Button-3>", self.context_menu)
        self.tree.bind("<Button-2>", self.context_menu)  # macOS secondary click

        self.empty = ttk.Label(list_frame, style="CardMuted.TLabel", justify="center")

        self._build_card()

    def shortcut(self, key: str, event: tk.Event) -> bool:
        actions = {
            "f": lambda: (self.search.focus_set(), self.search.select_range(0, "end")),
            "n": lambda: self.app.show("edit"),
            "g": lambda: self.app.show("generator"),
            "e": self.edit_selected,
            "b": self.copy_login,
            "t": self.copy_totp,
            "d": self.toggle_favorite,
        }
        # Ctrl+C in the list copies the password; in the search box it copies text.
        if key == "c" and event.widget is self.tree:
            self.copy_password()
            return True
        if key in actions:
            actions[key]()
            return True
        return False

    def _search_ctrl(self, event: tk.Event) -> str | None:
        # Entry binds Ctrl+B/D/T to cursor editing; in the search box ours take priority.
        if latin_key(event) in ("b", "d", "t", "e", "n", "g", "l"):
            return self.app._on_ctrl_key(event)
        return None

    def context_menu(self, event: tk.Event) -> None:
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        self.tree.focus(row)
        self._on_select()
        rec = self.selected
        if rec is None:
            return
        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label="Копировать пароль", accelerator="Enter",
                         command=self.copy_password)
        menu.add_command(label="Копировать логин", accelerator="Ctrl+B", command=self.copy_login)
        if rec.totp:
            menu.add_command(label="Копировать код 2FA", accelerator="Ctrl+T",
                             command=self.copy_totp)
        if rec.url:
            menu.add_command(label="Открыть сайт", command=self.open_url)
        menu.add_separator()
        menu.add_command(label="Убрать из избранного" if rec.favorite else "В избранное",
                         accelerator="Ctrl+D", command=self.toggle_favorite)
        menu.add_command(label="Изменить", accelerator="Ctrl+E", command=self.edit_selected)
        menu.add_command(label="Создать копию", command=self.duplicate)
        menu.add_separator()
        menu.add_command(label="Удалить", accelerator="Del", command=self.delete_selected)
        menu.tk_popup(event.x_root, event.y_root)

    def toggle_favorite(self) -> None:
        rec = self.selected
        if rec is None or self.app.vault is None:
            return
        self.app.vault.edit(rec.id, favorite=not rec.favorite)
        if self.app.save_vault():
            self.refresh(select=rec.id)

    def duplicate(self) -> None:
        rec = self.selected
        vault = self.app.vault
        if rec is None or vault is None:
            return
        data = rec.to_dict()
        for key in ("id", "created", "updated", "history"):
            data.pop(key)
        data["site"] = f"{rec.site} (копия)" if rec.site else rec.site
        new = vault.add(**data)
        if self.app.save_vault():
            self.app.show("edit", record_id=new.id)

    def add_tool(self, text: str, tip: str, command) -> ttk.Button:
        btn = ttk.Button(self.toolbar, text=text, style="Icon.TButton", width=2,
                         command=command)
        btn.pack(side="left")
        Tooltip(btn, tip, self.theme)
        return btn

    def _build_card(self) -> None:
        card = self.card = ttk.Frame(self.bottom, style="Card.TFrame", padding=(10, 8))
        card.columnconfigure(1, weight=1)
        head = ttk.Frame(card, style="Card.TFrame")
        head.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 4))
        self.lbl_title = ttk.Label(head, style="Card.TLabel", font=self.theme.font_bold)
        self.lbl_title.pack(side="left")
        self.lbl_folder = ttk.Label(head, style="CardMuted.TLabel")
        self.lbl_folder.pack(side="left", padx=(6, 0))

        def row(r: int, label: str) -> tuple[ttk.Label, ttk.Frame]:
            ttk.Label(card, text=label, style="CardMuted.TLabel").grid(
                row=r, column=0, sticky="w", padx=(0, 8))
            value = ttk.Label(card, style="Card.TLabel")
            value.grid(row=r, column=1, sticky="w")
            btns = ttk.Frame(card, style="Card.TFrame")
            btns.grid(row=r, column=2, sticky="e")
            return value, btns

        self.val_login, b = row(1, "Логин")
        self.card_button(b, "❐", "Копировать логин (Ctrl+B)", self.copy_login)
        self.val_password, b = row(2, "Пароль")
        self.val_password.configure(style="Mono.TLabel", font=self.theme.mono_small)
        self.btn_reveal = self.card_button(b, "◉", "Показать / скрыть", self.toggle_reveal)
        self.card_button(b, "❐", "Копировать пароль (Enter)", self.copy_password)
        self.row_totp = 3
        self.lbl_totp_name = ttk.Label(card, text="2FA", style="CardMuted.TLabel")
        self.val_totp = ttk.Label(card, style="Mono.TLabel")
        self.totp_btns = ttk.Frame(card, style="Card.TFrame")
        self.lbl_totp_left = ttk.Label(self.totp_btns, style="CardMuted.TLabel", width=4,
                                       anchor="e")
        self.lbl_totp_left.pack(side="left")
        self.card_button(self.totp_btns, "❐", "Копировать код 2FA (Ctrl+T)", self.copy_totp)

        actions = ttk.Frame(card, style="Card.TFrame")
        actions.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(6, 0))
        ttk.Button(actions, text="✎ Изменить", command=self.edit_selected).pack(side="left")
        self.btn_open = ttk.Button(actions, text="↗ Сайт", command=self.open_url)
        self.btn_open.pack(side="left", padx=(6, 0))
        ttk.Button(actions, text="✕", style="Danger.TButton", width=3,
                   command=self.delete_selected).pack(side="right")

        self.hint = ttk.Label(self.bottom, style="Muted.TLabel", justify="left",
                              text="Enter — пароль · Ctrl+B — логин · Ctrl+T — 2FA")

    def card_button(self, parent, text: str, tip: str, command) -> ttk.Button:
        btn = ttk.Button(parent, text=text, style="CardIcon.TButton", width=2, command=command)
        btn.pack(side="left")
        Tooltip(btn, tip, self.theme)
        return btn

    # -- data ------------------------------------------------------------

    def on_show(self, select: str | None = None, **_kwargs) -> None:
        self._sync_pin()
        self.refresh(select=select)
        self.after(30, self.search.focus_set)
        self._tick()

    def on_hide(self) -> None:
        if self._tick_job:
            self.after_cancel(self._tick_job)
            self._tick_job = None

    def records(self) -> list[Record]:
        vault = self.app.vault
        if vault is None:
            return []
        query = self.var_search.get().strip()
        recs = vault.search(query) if query else vault.all()
        if self.var_fav.get():
            recs = [r for r in recs if r.favorite]
        folder = self.var_folder.get()
        if folder not in ("", "Все папки"):
            recs = [r for r in recs if (r.folder or "Без папки") == folder]
        return sorted(recs, key=lambda r: (not r.favorite, r.title.lower()))

    def refresh(self, select: str | None = None) -> None:
        vault = self.app.vault
        if vault is None:
            return
        folders = vault.folders()
        values = ["Все папки", *folders]
        if any(not r.folder for r in vault.all()) and folders:
            values.append("Без папки")
        self.folder_box.configure(values=values)
        if self.var_folder.get() not in values:
            self.var_folder.set("Все папки")

        keep = select or (self.selected.id if self.selected else None)
        self.tree.delete(*self.tree.get_children())
        recs = self.records()
        for r in recs:
            title = ("★ " if r.favorite else "") + r.title
            self.tree.insert("", "end", iid=r.id, values=(title, r.login or r.email))
        total = len(vault.all())
        problems = audit(vault.all())
        bad = len({r.id for kind in ("weak", "reused", "empty") for r in problems[kind]})
        if bad:
            self.btn_audit.configure(text=f"⚠ {bad}")
            self.btn_audit.pack(side="right", padx=(0, 6))
        else:
            self.btn_audit.pack_forget()
        self.lbl_count.configure(text=f"{len(recs)} из {total}" if len(recs) != total
                                 else f"{total}")

        if not recs:
            text = ("Ничего не найдено" if total else
                    "Хранилище пустое\n\nНажмите ＋ или Ctrl+N,\nчтобы добавить первую запись")
            self.empty.configure(text=text)
            self.empty.place(relx=0.5, rely=0.45, anchor="center")
        else:
            self.empty.place_forget()

        if keep and self.tree.exists(keep):
            self.tree.selection_set(keep)
            self.tree.see(keep)
        elif recs and self.var_search.get():
            self.tree.selection_set(recs[0].id)
        else:
            self.tree.selection_set(())
        self._on_select()

    def _on_select(self) -> None:
        sel = self.tree.selection()
        rec = self.app.vault.get(sel[0]) if sel and self.app.vault else None
        if rec is not self.selected:
            self.revealed = False
        self.selected = rec
        if rec is None:
            self.card.pack_forget()
            self.hint.pack(fill="x", pady=(8, 0))
            return
        self.hint.pack_forget()
        self.card.pack(fill="x", pady=(8, 0))
        self.lbl_title.configure(text=("★ " if rec.favorite else "") + rec.title)
        self.lbl_folder.configure(text=rec.folder)
        self.val_login.configure(text=_short(rec.login or rec.email or "—", 30))
        self._show_password()
        if rec.totp:
            self.lbl_totp_name.grid(row=self.row_totp, column=0, sticky="w")
            self.val_totp.grid(row=self.row_totp, column=1, sticky="w")
            self.totp_btns.grid(row=self.row_totp, column=2, sticky="e")
        else:
            for w in (self.lbl_totp_name, self.val_totp, self.totp_btns):
                w.grid_remove()
        self.btn_open.configure(state="normal" if rec.url else "disabled")
        self._update_totp()

    def _show_password(self) -> None:
        rec = self.selected
        if rec is None:
            return
        text = _short(rec.password, 28) if self.revealed else MASK
        self.val_password.configure(text=text)

    def _update_totp(self) -> None:
        rec = self.selected
        if rec is None or not rec.totp:
            return
        try:
            code = totp(rec.totp)
        except ValueError:
            self.val_totp.configure(text="ошибка секрета")
            self.lbl_totp_left.configure(text="")
            return
        left = totp_remaining()
        self.val_totp.configure(text=f"{code[:3]} {code[3:]}",
                                foreground=self.theme.c["warn"] if left <= 5
                                else self.theme.c["fg"])
        self.lbl_totp_left.configure(text=f"{left}с")

    def _tick(self) -> None:
        self._update_totp()
        self._tick_job = self.after(1000, self._tick)

    # -- actions ---------------------------------------------------------

    def copy_password(self) -> None:
        if self.selected:
            self.app.copy(self.selected.password, "Пароль")

    def copy_login(self) -> None:
        if self.selected:
            self.app.copy(self.selected.login or self.selected.email, "Логин")

    def copy_totp(self) -> None:
        rec = self.selected
        if rec and rec.totp:
            try:
                self.app.copy(totp(rec.totp), "Код 2FA")
            except ValueError as e:
                self.app.toast(str(e), "error")

    def toggle_reveal(self) -> None:
        self.revealed = not self.revealed
        self._show_password()

    def open_url(self) -> None:
        rec = self.selected
        if rec and rec.url:
            _open_url(rec.url if "://" in rec.url else "https://" + rec.url)

    def edit_selected(self) -> None:
        if self.selected:
            self.app.show("edit", record_id=self.selected.id)

    def delete_selected(self) -> None:
        rec = self.selected
        vault = self.app.vault
        if rec is None or vault is None:
            return
        if not messagebox.askyesno(APP_TITLE, f"Удалить запись «{rec.title}»?",
                                   parent=self.app.root):
            return
        vault.delete(rec.id)
        if self.app.save_vault():
            self.selected = None
            self.refresh()
            self.app.toast("Запись удалена")

    def toggle_pin(self) -> None:
        self.app.set_topmost(not self.app.settings.always_on_top)
        self._sync_pin()

    def _sync_pin(self) -> None:
        self.btn_pin.configure(style="IconOn.TButton" if self.app.settings.always_on_top
                               else "Icon.TButton")

    def _focus_list(self) -> None:
        children = self.tree.get_children()
        if not children:
            return
        self.tree.focus_set()
        target = self.tree.selection()[0] if self.tree.selection() else children[0]
        self.tree.selection_set(target)
        self.tree.focus(target)

    def _enter_from_search(self) -> None:
        if self.selected:
            self.copy_password()
        else:
            self._focus_list()

    def _type_to_search(self, event: tk.Event) -> None:
        if event.char and event.char.isprintable() and not event.state & 0x4:
            self.search.focus_set()
            self.search.insert("end", event.char)


class EditScreen(Screen):
    name = "edit"

    def build(self) -> None:
        self.record_id: str | None = None
        self.vars = {k: tk.StringVar() for k in
                     ("site", "url", "login", "email", "password", "totp", "folder", "tags")}
        self.var_fav = tk.BooleanVar()
        self.var_show = tk.BooleanVar(value=False)

        bar = self.header("Новая запись")
        self.lbl_head = bar.winfo_children()[-1]
        star = Toggle(bar, self.var_fav, "★", "☆")
        star.pack(side="right")
        Tooltip(star, "Избранное", self.theme)

        form = ttk.Frame(self)
        form.pack(fill="both", expand=True)
        form.columnconfigure(1, weight=1)
        self.entries: dict[str, ttk.Entry] = {}

        def field(r: int, key: str, label: str) -> ttk.Entry:
            ttk.Label(form, text=label, style="Muted.TLabel").grid(
                row=r, column=0, sticky="w", padx=(0, 8), pady=3)
            entry = ttk.Entry(form, textvariable=self.vars[key])
            entry.grid(row=r, column=1, sticky="ew", pady=3)
            self.entries[key] = entry
            return entry

        field(0, "site", "Название")
        field(1, "url", "Сайт (URL)")
        field(2, "login", "Логин")
        field(3, "email", "E-mail")

        ttk.Label(form, text="Пароль", style="Muted.TLabel").grid(
            row=4, column=0, sticky="w", padx=(0, 8), pady=(3, 0))
        pw = ttk.Frame(form)
        pw.grid(row=4, column=1, sticky="ew", pady=(3, 0))
        self.entry_password = ttk.Entry(pw, textvariable=self.vars["password"], show="•",
                                        font=self.theme.mono_small)
        self.entry_password.pack(side="left", fill="x", expand=True)
        Toggle(pw, self.var_show, "◉", "○", command=self._toggle_show).pack(
            side="left", padx=(4, 0))
        gen = ttk.Button(pw, text="⚄", style="Icon.TButton", width=2, command=self.quick_generate)
        gen.pack(side="left")
        gen.bind("<Button-3>", lambda _e: self.app.show("generator", for_edit=True))
        Tooltip(gen, "Сгенерировать · правый клик — настройки", self.theme)
        self.entries["password"] = self.entry_password

        meter = ttk.Frame(form)
        meter.grid(row=5, column=1, sticky="ew", pady=(2, 3))
        self.bar = StrengthBar(meter, self.theme)
        self.bar.pack(fill="x", pady=(2, 0))
        self.lbl_strength = ttk.Label(meter, style="Muted.TLabel")
        self.lbl_strength.pack(anchor="w")
        self.vars["password"].trace_add("write", lambda *_: self._update_strength())

        field(6, "totp", "Секрет 2FA")
        ttk.Label(form, text="Папка", style="Muted.TLabel").grid(
            row=7, column=0, sticky="w", padx=(0, 8), pady=3)
        self.folder_box = ttk.Combobox(form, textvariable=self.vars["folder"])
        self.folder_box.grid(row=7, column=1, sticky="ew", pady=3)
        field(8, "tags", "Теги")

        ttk.Label(form, text="Заметка", style="Muted.TLabel").grid(
            row=9, column=0, sticky="nw", padx=(0, 8), pady=3)
        self.note = tk.Text(form, height=3, wrap="word", **self.theme.text_widget_options())
        self.note.grid(row=9, column=1, sticky="nsew", pady=3)
        form.rowconfigure(9, weight=1)

        self.lbl_meta = ttk.Label(form, style="Muted.TLabel")
        self.lbl_meta.grid(row=10, column=0, columnspan=2, sticky="w", pady=(2, 0))
        self.btn_history = ttk.Button(form, style="Link.TButton", command=self.show_history)

        btns = ttk.Frame(self)
        btns.pack(fill="x", pady=(8, 8))
        ttk.Button(btns, text="Сохранить", style="Accent.TButton",
                   command=self.save).pack(side="right")
        ttk.Button(btns, text="Отмена", command=self.cancel).pack(side="right", padx=(0, 6))
        self.bind_all_keys()

    def bind_all_keys(self) -> None:
        for widget in (*self.entries.values(), self.folder_box):
            widget.bind("<Return>", lambda _e: self.save())

    def on_escape(self) -> None:
        self.cancel()

    def shortcut(self, key: str, event: tk.Event) -> bool:
        if key == "s":
            self.save()
            return True
        if key == "g":
            self.quick_generate()
            return True
        return False

    def on_show(self, record_id: str | None = None, password: str | None = None,
                keep: bool = False, **_kwargs) -> None:
        vault = self.app.vault
        if vault is None:
            self.app.show("lock")
            return
        if keep:
            # Back from the generator: the form still holds what was typed.
            if password is not None:
                self.vars["password"].set(password)
                self.var_show.set(True)
                self._toggle_show()
            return
        rec = vault.get(record_id) if record_id else None
        self.record_id = rec.id if rec else None
        self.lbl_head.configure(text="Изменить запись" if rec else "Новая запись")
        values = rec.to_dict() if rec else {}
        for key, var in self.vars.items():
            value = values.get(key, "")
            var.set(", ".join(value) if key == "tags" else value)
        self.var_fav.set(bool(values.get("favorite", False)))
        self.note.delete("1.0", "end")
        self.note.insert("1.0", values.get("note", ""))
        self.folder_box.configure(values=vault.folders())
        if password is not None:
            self.vars["password"].set(password)
        elif rec is None:
            self.quick_generate()
        self.var_show.set(rec is None)
        self._toggle_show()
        if rec:
            self.lbl_meta.configure(text=f"Создано {rec.created[:16]}"
                                    + (f" · изменено {rec.updated[:16]}" if rec.updated else ""))
        else:
            self.lbl_meta.configure(text="")
        if rec and rec.history:
            self.btn_history.configure(text=f"Старые пароли ({len(rec.history)})")
            self.btn_history.grid(row=10, column=1, sticky="e")
        else:
            self.btn_history.grid_remove()
        self.after(30, lambda: self.entries["site"].focus_set())

    def _toggle_show(self) -> None:
        self.entry_password.configure(show="" if self.var_show.get() else "•")

    def _update_strength(self) -> None:
        text, bits = strength_text(self.vars["password"].get())
        self.lbl_strength.configure(text=text, foreground=self.theme.strength_color(bits))
        self.bar.set(bits)

    def quick_generate(self) -> None:
        try:
            self.vars["password"].set(generate_from_settings(self.app.settings))
        except ValueError as e:
            self.app.toast(str(e), "error")
            return
        self.var_show.set(True)
        self._toggle_show()

    def collect(self) -> dict:
        data = {k: v.get().strip() for k, v in self.vars.items()}
        data["password"] = self.vars["password"].get()  # spaces may be intentional
        data["tags"] = [t.strip() for t in data["tags"].split(",") if t.strip()]
        data["favorite"] = self.var_fav.get()
        data["note"] = self.note.get("1.0", "end-1c").strip()
        return data

    def save(self) -> None:
        vault = self.app.vault
        if vault is None:
            return
        data = self.collect()
        if not data["password"]:
            self.app.toast("Пароль не может быть пустым", "error")
            self.entry_password.focus_set()
            return
        if not (data["site"] or data["url"] or data["login"]):
            self.app.toast("Заполните название, сайт или логин", "error")
            self.entries["site"].focus_set()
            return
        if data["totp"]:
            try:
                data["totp"] = normalize_totp_secret(data["totp"])
            except ValueError as e:
                self.app.toast(str(e), "error")
                self.entries["totp"].focus_set()
                return
        if self.record_id:
            vault.edit(self.record_id, **data)
            rec_id = self.record_id
        else:
            rec_id = vault.add(**data).id
        if self.app.save_vault():
            self.app.toast("Сохранено", "ok")
            self.app.show("list", select=rec_id)

    def cancel(self) -> None:
        self.app.show("list")

    def show_history(self) -> None:
        rec = self.app.vault.get(self.record_id) if self.app.vault and self.record_id else None
        if rec is None or not rec.history:
            return
        menu = tk.Menu(self, tearoff=False)
        for item in rec.history:
            label = f"{item.get('changed', '')[:16]}   {_short(item.get('password', ''), 24)}"
            menu.add_command(label=label,
                             command=lambda p=item.get("password", ""): self.app.copy(p, "Пароль"))
        menu.add_separator()
        menu.add_command(label="Нажмите на строку, чтобы скопировать", state="disabled")
        x = self.btn_history.winfo_rootx()
        y = self.btn_history.winfo_rooty() + self.btn_history.winfo_height()
        menu.tk_popup(x, y)


class GeneratorScreen(Screen):
    name = "generator"

    def build(self) -> None:
        st = self.app.settings
        self.back = "list"
        self.for_edit = False
        self.var_mode = tk.StringVar(value=st.gen_mode)
        self.var_length = tk.IntVar(value=st.gen_length)
        self.var_lower = tk.BooleanVar(value=st.gen_lower)
        self.var_upper = tk.BooleanVar(value=st.gen_upper)
        self.var_digits = tk.BooleanVar(value=st.gen_digits)
        self.var_symbols = tk.BooleanVar(value=st.gen_symbols)
        self.var_full = tk.BooleanVar(value=st.gen_full_symbols)
        self.var_ambiguous = tk.BooleanVar(value=st.gen_exclude_ambiguous)
        self.var_words = tk.IntVar(value=st.gen_words)
        self.var_sep = tk.StringVar(value=st.gen_separator)
        self.var_pin = tk.IntVar(value=st.gen_pin_length)
        self.password = ""

        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 8))
        self.btn_back = ttk.Button(bar, text="←", style="Icon.TButton", width=2,
                                   command=self.go_back)
        self.btn_back.pack(side="left")
        ttk.Label(bar, text="Генератор", style="Title.TLabel").pack(side="left", padx=(4, 0))

        seg = ttk.Frame(self)
        seg.pack(fill="x")
        for i, (value, text) in enumerate((("password", "Пароль"), ("passphrase", "Фраза"),
                                           ("pin", "PIN"))):
            seg.columnconfigure(i, weight=1, uniform="seg")
            ttk.Radiobutton(seg, text=text, value=value, variable=self.var_mode,
                            style="Segment.TRadiobutton", command=self.on_mode).grid(
                row=0, column=i, sticky="ew")

        card = ttk.Frame(self, style="Card.TFrame", padding=(12, 12))
        card.pack(fill="x", pady=(10, 0))
        self.lbl_out = ttk.Label(card, style="MonoBig.TLabel", wraplength=320,
                                 justify="center", anchor="center", cursor="hand2")
        self.lbl_out.pack(fill="x", ipady=6)
        self.lbl_out.bind("<Button-1>", lambda _e: self.copy())
        self.lbl_out.bind("<Configure>",
                          lambda e: self.lbl_out.configure(wraplength=max(e.width - 8, 100)))
        self.bar = StrengthBar(card, self.theme)
        self.bar.pack(fill="x", pady=(8, 2))
        self.lbl_strength = ttk.Label(card, style="CardMuted.TLabel")
        self.lbl_strength.pack(anchor="w")

        btns = ttk.Frame(self)
        btns.pack(fill="x", pady=(8, 0))
        btns.columnconfigure((0, 1, 2), weight=1, uniform="b")
        ttk.Button(btns, text="↻ Ещё", style="Accent.TButton",
                   command=self.generate).grid(row=0, column=0, sticky="ew")
        ttk.Button(btns, text="Копировать", command=self.copy).grid(
            row=0, column=1, sticky="ew", padx=6)
        self.btn_save = ttk.Button(btns, command=self.use)
        self.btn_save.grid(row=0, column=2, sticky="ew")

        self.opts = ttk.Frame(self)
        self.opts.pack(fill="both", expand=True, pady=(12, 0))
        self._build_password_opts()
        self._build_phrase_opts()
        self._build_pin_opts()

        for var in (self.var_lower, self.var_upper, self.var_digits, self.var_symbols,
                    self.var_full, self.var_ambiguous, self.var_sep):
            var.trace_add("write", lambda *_: self.on_change())

    def _slider(self, parent, label: str, var: tk.IntVar, lo: int, hi: int) -> None:
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=(0, 6))
        ttk.Label(row, text=label).pack(side="left")
        value = ttk.Label(row, text=str(var.get()), width=3, anchor="e", style="Bold.TLabel")
        value.pack(side="right")

        def moved(v: str) -> None:
            n = int(float(v))
            if n != var.get():
                var.set(n)
                self.on_change()
            value.configure(text=str(n))

        scale = ttk.Scale(row, from_=lo, to=hi, orient="horizontal", command=moved)
        scale.set(var.get())
        scale.pack(side="left", fill="x", expand=True, padx=8)

    def _build_password_opts(self) -> None:
        f = self.f_password = ttk.Frame(self.opts)
        self._slider(f, "Длина", self.var_length, MIN_LENGTH, 64)
        grid = ttk.Frame(f)
        grid.pack(fill="x")
        for i, (text, var) in enumerate((("a–z", self.var_lower), ("A–Z", self.var_upper),
                                         ("0–9", self.var_digits), ("!#$%", self.var_symbols))):
            grid.columnconfigure(i, weight=1, uniform="c")
            ttk.Checkbutton(grid, text=text, variable=var).grid(row=0, column=i, sticky="w")
        ttk.Checkbutton(f, text="Без похожих символов (I l 1 O 0)",
                        variable=self.var_ambiguous).pack(anchor="w", pady=(8, 0))
        ttk.Checkbutton(f, text="Все символы, включая кавычки и \\",
                        variable=self.var_full).pack(anchor="w", pady=(4, 0))

    def _build_phrase_opts(self) -> None:
        f = self.f_phrase = ttk.Frame(self.opts)
        self._slider(f, "Слов", self.var_words, PASSPHRASE_MIN_WORDS, PASSPHRASE_MAX_WORDS)
        row = ttk.Frame(f)
        row.pack(fill="x")
        ttk.Label(row, text="Разделитель").pack(side="left")
        box = ttk.Combobox(row, textvariable=self.var_sep, width=4,
                           values=["-", ".", "_", " ", "+", "/"])
        box.pack(side="left", padx=8)
        ttk.Label(f, style="Muted.TLabel", wraplength=330, justify="left",
                  text="Произносимые слова легче набрать и запомнить. "
                       "Стойкость считается точно.").pack(anchor="w", pady=(8, 0))

    def _build_pin_opts(self) -> None:
        f = self.f_pin = ttk.Frame(self.opts)
        self._slider(f, "Цифр", self.var_pin, 4, 12)
        ttk.Label(f, style="Muted.TLabel", wraplength=330, justify="left",
                  text="Только для карт, телефонов и замков: "
                       "как пароль от сайта PIN слабый.").pack(anchor="w", pady=(4, 0))

    def shortcut(self, key: str, event: tk.Event) -> bool:
        if key == "c" and not isinstance(event.widget, (ttk.Entry, ttk.Combobox)):
            self.copy()
            return True
        if key in ("g", "r"):
            self.generate()
            return True
        return False

    def on_show(self, back: str = "list", for_edit: bool = False, **_kwargs) -> None:
        self.back = back
        self.after(30, self.focus_set)
        self.for_edit = for_edit
        if for_edit:
            self.btn_save.configure(text="✓ Вставить", state="normal")
        elif self.app.vault is not None:
            self.btn_save.configure(text="В запись", state="normal")
        else:
            self.btn_save.configure(text="В запись", state="disabled")
        self.on_mode(save=False)

    def on_escape(self) -> None:
        self.go_back()

    def go_back(self) -> None:
        if self.for_edit:
            self.app.show("edit", keep=True)
        else:
            self.app.show(self.back)

    def on_mode(self, save: bool = True) -> None:
        for f in (self.f_password, self.f_phrase, self.f_pin):
            f.pack_forget()
        {"password": self.f_password, "passphrase": self.f_phrase,
         "pin": self.f_pin}[self.var_mode.get()].pack(fill="both", expand=True)
        self.on_change(save=save)

    def on_change(self, save: bool = True) -> None:
        st = self.app.settings
        st.gen_mode = self.var_mode.get()
        st.gen_length = self.var_length.get()
        st.gen_lower, st.gen_upper = self.var_lower.get(), self.var_upper.get()
        st.gen_digits, st.gen_symbols = self.var_digits.get(), self.var_symbols.get()
        st.gen_full_symbols = self.var_full.get()
        st.gen_exclude_ambiguous = self.var_ambiguous.get()
        st.gen_words = self.var_words.get()
        st.gen_separator = self.var_sep.get()[:3]
        st.gen_pin_length = self.var_pin.get()
        if save:
            self.app.save_settings()
        self.generate()

    def generate(self) -> None:
        st = self.app.settings
        try:
            self.password = generate_from_settings(st)
        except ValueError as e:
            self.password = ""
            self.lbl_out.configure(text="—")
            self.lbl_strength.configure(text=str(e), foreground=self.theme.c["danger"])
            self.bar.set(0)
            return
        if st.gen_mode == "passphrase":
            bits = passphrase_entropy(st.gen_words)
        elif st.gen_mode == "pin":
            bits = st.gen_pin_length * 3.32
        else:
            bits = estimate_entropy(self.password)
        self.lbl_out.configure(text=self.password)
        self.lbl_strength.configure(text=f"{strength_label(bits)} · {bits:.0f} бит · "
                                         f"{len(self.password)} симв.",
                                    foreground=self.theme.strength_color(bits))
        self.bar.set(bits)

    def copy(self) -> None:
        self.app.copy(self.password, "Пароль")

    def use(self) -> None:
        if not self.password:
            return
        if self.for_edit:
            self.app.show("edit", keep=True, password=self.password)
        elif self.app.vault is not None:
            self.app.show("edit", password=self.password)


class SettingsScreen(Screen):
    name = "settings"

    def build(self) -> None:
        st = self.app.settings
        self.header("Настройки")
        scroll = ScrollFrame(self, self.theme)
        scroll.pack(fill="both", expand=True)
        body = scroll.inner
        body.configure(padding=(0, 0, 8, 12))

        self.var_theme = tk.StringVar(value=st.theme)
        self.var_top = tk.BooleanVar(value=st.always_on_top)
        self.var_autolock = tk.IntVar(value=st.auto_lock_minutes)
        self.var_clip = tk.IntVar(value=st.clipboard_seconds)
        self.var_minimize = tk.BooleanVar(value=st.lock_on_minimize)
        self.var_backups = tk.BooleanVar(value=st.backups)

        self.section(body, "Внешний вид")
        seg = ttk.Frame(body)
        seg.pack(fill="x")
        for i, (value, text) in enumerate((("dark", "Тёмная"), ("light", "Светлая"))):
            seg.columnconfigure(i, weight=1, uniform="t")
            ttk.Radiobutton(seg, text=text, value=value, variable=self.var_theme,
                            style="Segment.TRadiobutton",
                            command=lambda: self.app.set_theme(self.var_theme.get())).grid(
                row=0, column=i, sticky="ew")
        ttk.Checkbutton(body, text="Поверх всех окон", variable=self.var_top,
                        command=lambda: self.app.set_topmost(self.var_top.get())).pack(
            anchor="w", pady=(8, 0))

        self.section(body, "Безопасность")
        self.spin_row(body, "Блокировать через", self.var_autolock, 0, 240, "мин без действий")
        self.spin_row(body, "Очищать буфер через", self.var_clip, 0, 600, "с")
        ttk.Checkbutton(body, text="Блокировать при сворачивании окна",
                        variable=self.var_minimize, command=self.apply).pack(anchor="w")
        ttk.Checkbutton(body, text="Резервная копия при каждом сохранении",
                        variable=self.var_backups, command=self.apply).pack(anchor="w", pady=(4, 0))
        ttk.Label(body, text="0 — не блокировать / не очищать", style="Muted.TLabel").pack(
            anchor="w", pady=(4, 0))

        self.vault_widgets: list[ttk.Button] = []
        self.section(body, "Хранилище")
        self.lbl_path = ttk.Label(body, style="Muted.TLabel", wraplength=300, justify="left")
        self.lbl_path.pack(anchor="w")
        self.buttons(body, (("Сменить пароль…", self.change_master),
                            ("Резервные копии", self.open_backups)))

        self.section(body, "Импорт")
        self.buttons(body, (("Из CSV…", self.import_csv),
                            ("Из .awpe / .json…", self.import_file)))
        ttk.Label(body, style="Muted.TLabel", wraplength=300, justify="left",
                  text="CSV из Chrome, Edge, Firefox, Bitwarden, KeePass, 1Password, "
                       "LastPass. Дубликаты пропускаются.").pack(anchor="w", pady=(4, 0))

        self.section(body, "Экспорт")
        self.buttons(body, (("Зашифрованный…", self.export_encrypted),
                            ("В CSV…", self.export_csv)))

        self.section(body, "Опасная зона")
        btn = ttk.Button(body, text="Удалить хранилище…", style="Danger.TButton",
                         command=self.delete_vault)
        btn.pack(anchor="w")
        self.vault_widgets.append(btn)

        self.section(body, "О программе")
        ttk.Label(body, text=f"{APP_TITLE} {__version__} · MIT\nРаботает без интернета, "
                             "ничего никуда не отправляет.",
                  style="Muted.TLabel", justify="left", wraplength=300).pack(anchor="w")
        ttk.Button(body, text="github.com/AWProger/gen_pass", style="Link.TButton",
                   command=lambda: _open_url("https://github.com/AWProger/gen_pass")).pack(
            anchor="w")

    def section(self, parent, title: str) -> None:
        ttk.Label(parent, text=title, style="Bold.TLabel").pack(anchor="w", pady=(14, 6))

    def spin_row(self, parent, label: str, var: tk.IntVar, lo: int, hi: int, unit: str) -> None:
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=(0, 6))
        ttk.Label(row, text=label).pack(side="left")
        spin = ttk.Spinbox(row, from_=lo, to=hi, textvariable=var, width=5,
                           command=self.apply)
        spin.pack(side="left", padx=6)
        spin.bind("<FocusOut>", lambda _e: self.apply())
        spin.bind("<Return>", lambda _e: self.apply())
        ttk.Label(row, text=unit, style="Muted.TLabel").pack(side="left")

    def buttons(self, parent, items) -> None:
        row = ttk.Frame(parent)
        row.pack(fill="x")
        for i, (text, command) in enumerate(items):
            row.columnconfigure(i, weight=1, uniform="b")
            btn = ttk.Button(row, text=text, command=command)
            btn.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 6, 0))
            self.vault_widgets.append(btn)

    def on_show(self, **_kwargs) -> None:
        self.var_top.set(self.app.settings.always_on_top)
        vault = self.app.vault
        self.lbl_path.configure(text=str(vault.path if vault else self.app.settings.vault_file()))
        state = "normal" if vault else "disabled"
        for btn in self.vault_widgets:
            btn.configure(state=state)

    def on_hide(self) -> None:
        self.apply()

    def on_escape(self) -> None:
        self.app.show("list" if self.app.vault else "lock")

    def apply(self) -> None:
        st = self.app.settings

        def number(var: tk.IntVar, lo: int, hi: int, default: int) -> int:
            try:
                return max(lo, min(hi, int(var.get())))
            except (tk.TclError, ValueError):
                return default

        st.auto_lock_minutes = number(self.var_autolock, 0, 240, st.auto_lock_minutes)
        st.clipboard_seconds = number(self.var_clip, 0, 600, st.clipboard_seconds)
        self.var_autolock.set(st.auto_lock_minutes)
        self.var_clip.set(st.clipboard_seconds)
        st.lock_on_minimize = self.var_minimize.get()
        st.backups = self.var_backups.get()
        if self.app.vault:
            self.app.vault.backups = st.backups
        self.app.save_settings()

    # -- vault actions ---------------------------------------------------

    def change_master(self) -> None:
        vault = self.app.vault
        if vault is None:
            return

        def check(values: list[str]) -> str:
            old, new, again = values
            if not vault.verify(old):
                return "Текущий пароль неверен"
            if len(new) < 8:
                return "Новый пароль короче 8 символов"
            if new != new.strip():
                return "Уберите пробелы в начале или в конце"
            if new != again:
                return "Новые пароли не совпадают"
            return ""

        values = ask_passwords(self.app, "Смена мастер-пароля",
                               ["Текущий пароль", "Новый пароль", "Ещё раз"], check)
        if not values:
            return
        try:
            vault.change_passphrase(values[0], values[1])
        except (ValueError, OSError) as e:
            messagebox.showerror(APP_TITLE, f"Не удалось сменить пароль: {e}",
                                 parent=self.app.root)
            return
        self.app.toast("Мастер-пароль изменён", "ok")

    def open_backups(self) -> None:
        vault = self.app.vault
        if vault is None:
            return
        backups = vault.list_backups()
        if not backups:
            messagebox.showinfo(APP_TITLE, "Резервных копий пока нет. Они появляются при "
                                "каждом сохранении.", parent=self.app.root)
            return
        _open_path(vault.backup_dir)
        self.app.toast(f"Копий: {len(backups)}. Любую можно открыть через «Другой файл…»")

    def _merge(self, records: list[Record], source: str) -> None:
        vault = self.app.vault
        if vault is None:
            return
        if not records:
            messagebox.showinfo(APP_TITLE, "В файле нет записей.", parent=self.app.root)
            return
        if not messagebox.askyesno(APP_TITLE, f"Добавить записей из {source}: {len(records)}?\n"
                                   "Существующие записи останутся, дубликаты будут пропущены.",
                                   parent=self.app.root):
            return
        added, skipped = vault.merge(records)
        if self.app.save_vault():
            self.app.toast(f"Добавлено: {added}" + (f", пропущено дубликатов: {skipped}"
                                                     if skipped else ""), "ok")

    def import_csv(self) -> None:
        path = filedialog.askopenfilename(parent=self.app.root, title="Импорт из CSV",
                                          filetypes=[("CSV", "*.csv"), ("Все файлы", "*.*")])
        if not path:
            return
        try:
            records = import_csv(path)
        except (ValueError, OSError, UnicodeDecodeError) as e:
            messagebox.showerror(APP_TITLE, f"Импорт не удался: {e}", parent=self.app.root)
            return
        self._merge(records, "CSV")

    def import_file(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.app.root, title="Импорт",
            filetypes=[("Экспорт", "*.awpe *.json"), ("Все файлы", "*.*")])
        if not path:
            return
        try:
            if Path(path).read_bytes()[:4] == b"AWPE":
                values = ask_passwords(self.app, "Пароль от файла", ["Пароль экспорта"])
                if not values:
                    return
                records = import_encrypted(path, values[0])
            else:
                records = import_json(path)
        except (ValueError, OSError, UnicodeDecodeError) as e:
            messagebox.showerror(APP_TITLE, f"Импорт не удался: {e}", parent=self.app.root)
            return
        self._merge(records, "файла")

    def export_encrypted(self) -> None:
        vault = self.app.vault
        if vault is None or not self._has_records():
            return

        def check(values: list[str]) -> str:
            if len(values[0]) < 8:
                return "Пароль короче 8 символов"
            return "" if values[0] == values[1] else "Пароли не совпадают"

        values = ask_passwords(self.app, "Пароль для файла экспорта",
                               ["Пароль", "Ещё раз"], check,
                               note="Можно указать мастер-пароль или другой.")
        if not values:
            return
        path = filedialog.asksaveasfilename(parent=self.app.root, title="Экспорт",
                                            defaultextension=".awpe",
                                            filetypes=[("Зашифрованный экспорт", "*.awpe")])
        if not path:
            return
        try:
            export_encrypted(vault.all(), path, values[0])
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Ошибка экспорта: {e}", parent=self.app.root)
            return
        self.app.toast(f"Экспортировано записей: {len(vault.all())}", "ok")

    def export_csv(self) -> None:
        vault = self.app.vault
        if vault is None or not self._has_records():
            return
        if not messagebox.askyesno(
                APP_TITLE, "CSV записывает пароли обычным текстом. Любой, кто прочитает "
                "файл, увидит все пароли.\n\nУдалите файл сразу после переноса. Продолжить?",
                icon="warning", parent=self.app.root):
            return
        path = filedialog.asksaveasfilename(parent=self.app.root, title="Экспорт в CSV",
                                            defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        try:
            export_csv(vault.all(), path)
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Ошибка экспорта: {e}", parent=self.app.root)
            return
        self.app.toast(f"Экспортировано записей: {len(vault.all())}", "ok")

    def _has_records(self) -> bool:
        if self.app.vault and self.app.vault.all():
            return True
        messagebox.showinfo(APP_TITLE, "Нечего экспортировать: хранилище пусто.",
                            parent=self.app.root)
        return False

    def delete_vault(self) -> None:
        vault = self.app.vault
        if vault is None:
            return
        if not messagebox.askyesno(
                APP_TITLE, f"Удалить файл хранилища?\n\n{vault.path}\n\n"
                "Все пароли будут потеряны. Резервные копии останутся в папке backups.",
                icon="warning", parent=self.app.root):
            return
        values = ask_passwords(self.app, "Подтвердите удаление", ["Мастер-пароль"],
                               lambda v: "" if vault.verify(v[0]) else "Неверный пароль")
        if not values:
            return
        try:
            vault.path.unlink(missing_ok=True)
            vault.path.with_suffix(".salt").unlink(missing_ok=True)
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Не удалось удалить: {e}", parent=self.app.root)
            return
        self.app.vault = None
        self.app.show("lock")
        self.app.toast("Хранилище удалено")


class AuditScreen(Screen):
    name = "audit"

    KINDS = (
        ("weak", "Слабые", "меньше 60 бит — подбираются перебором"),
        ("reused", "Повторяются", "утечка на одном сайте откроет и другие"),
        ("old", "Старые", "не менялись больше года"),
        ("empty", "Пустые", "запись без пароля"),
    )
    SHORT = {"weak": "слабый", "reused": "повтор", "old": "старый", "empty": "пустой"}

    def build(self) -> None:
        self.header("Проверка паролей")
        self.summary = ttk.Frame(self)
        self.summary.pack(fill="x")
        self.summary.columnconfigure(1, weight=1)
        self.counts: dict[str, ttk.Label] = {}
        for row, (kind, title, hint) in enumerate(self.KINDS):
            count = ttk.Label(self.summary, style="Title.TLabel", width=3, anchor="e")
            count.grid(row=row, column=0, sticky="e", padx=(0, 10), pady=2)
            text = ttk.Frame(self.summary)
            text.grid(row=row, column=1, sticky="w", pady=2)
            ttk.Label(text, text=title, style="Bold.TLabel").pack(anchor="w")
            ttk.Label(text, text=hint, style="Muted.TLabel").pack(anchor="w")
            self.counts[kind] = count

        self.lbl_ok = ttk.Label(self, style="Ok.TLabel", wraplength=320, justify="left")
        frame = ttk.Frame(self, style="Card.TFrame")
        frame.pack(fill="both", expand=True, pady=(10, 0))
        self.tree = ttk.Treeview(frame, columns=("title", "issue"), show="",
                                 selectmode="browse", height=4)
        self.tree.column("title", width=180, stretch=True)
        self.tree.column("issue", width=120, stretch=False)
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda _e: self.open_selected())
        self.tree.bind("<Return>", lambda _e: self.open_selected())
        ttk.Label(self, text="Двойной клик — открыть и сменить пароль",
                  style="Muted.TLabel").pack(anchor="w", pady=(6, 8))

    def on_show(self, **_kwargs) -> None:
        vault = self.app.vault
        if vault is None:
            self.app.show("lock")
            return
        result = audit(vault.all())
        issues: dict[str, list[str]] = {}
        for kind, _title, _hint in self.KINDS:
            recs = result[kind]
            self.counts[kind].configure(
                text=str(len(recs)),
                foreground=self.theme.c["danger" if recs and kind != "old" else
                                        "warn" if recs else "ok"])
            for r in recs:
                issues.setdefault(r.id, []).append(self.SHORT[kind])
        self.tree.delete(*self.tree.get_children())
        for rec in sorted(vault.all(), key=lambda r: r.title.lower()):
            if rec.id in issues:
                self.tree.insert("", "end", iid=rec.id,
                                 values=(rec.title, ", ".join(issues[rec.id])))
        if not issues:
            self.lbl_ok.configure(text="Проблем не найдено. Все пароли стойкие и разные.")
            self.lbl_ok.pack(fill="x", pady=(10, 0), after=self.summary)
        else:
            self.lbl_ok.pack_forget()

    def on_escape(self) -> None:
        self.app.show("list")

    def open_selected(self) -> None:
        sel = self.tree.selection()
        if sel:
            self.app.show("edit", record_id=sel[0])


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------

class Tooltip:
    """Small hint shown after hovering a widget for a moment."""

    def __init__(self, widget: tk.Widget, text: str, theme: Theme) -> None:
        self.widget, self.text, self.theme = widget, text, theme
        self.tip: tk.Toplevel | None = None
        self.job: str | None = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _e=None) -> None:
        self._hide()
        self.job = self.widget.after(600, self._show)

    def _show(self) -> None:
        if self.tip or not self.widget.winfo_exists():
            return
        x = self.widget.winfo_rootx()
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.attributes("-topmost", True)
        tk.Label(self.tip, text=self.text, bg=self.theme.c["surface2"], fg=self.theme.c["fg"],
                 font=self.theme.font_small, padx=6, pady=3, relief="flat").pack()
        self.tip.update_idletasks()
        # Keep the hint on screen near the right edge.
        width = self.tip.winfo_width()
        screen = self.widget.winfo_screenwidth()
        self.tip.wm_geometry(f"+{min(x, screen - width - 4)}+{y}")

    def _hide(self, _e=None) -> None:
        if self.job:
            self.widget.after_cancel(self.job)
            self.job = None
        if self.tip:
            self.tip.destroy()
            self.tip = None


def ask_passwords(app: App, title: str, labels: list[str], check=None,
                  note: str = "") -> list[str] | None:
    """Small modal dialog with masked fields. Returns the values, or None on cancel."""
    root = app.root
    dlg = tk.Toplevel(root)
    dlg.title(title)
    dlg.configure(bg=app.theme.c["bg"])
    dlg.transient(root)
    dlg.resizable(False, False)
    dlg.attributes("-topmost", app.settings.always_on_top)
    frame = ttk.Frame(dlg, padding=16)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text=title, style="Bold.TLabel").pack(anchor="w", pady=(0, 8))
    if note:
        ttk.Label(frame, text=note, style="Muted.TLabel", wraplength=260).pack(
            anchor="w", pady=(0, 8))
    vars_ = [tk.StringVar() for _ in labels]
    entries = []
    for label, var in zip(labels, vars_, strict=True):
        ttk.Label(frame, text=label, style="Muted.TLabel").pack(anchor="w")
        entry = ttk.Entry(frame, textvariable=var, show="•", width=32)
        entry.pack(fill="x", pady=(2, 8))
        entries.append(entry)
    error = ttk.Label(frame, style="Danger.TLabel", wraplength=260)
    error.pack(anchor="w")
    result: list[list[str] | None] = [None]

    def ok(_e=None) -> None:
        values = [v.get() for v in vars_]
        if not values[0]:
            error.configure(text="Введите пароль")
            return
        message = check(values) if check else ""
        if message:
            error.configure(text=message)
            return
        result[0] = values
        dlg.destroy()

    btns = ttk.Frame(frame)
    btns.pack(fill="x", pady=(8, 0))
    ttk.Button(btns, text="OK", style="Accent.TButton", command=ok).pack(side="right")
    ttk.Button(btns, text="Отмена", command=dlg.destroy).pack(side="right", padx=(0, 6))
    dlg.bind("<Return>", ok)
    dlg.bind("<Escape>", lambda _e: dlg.destroy())
    dlg.update_idletasks()
    x = root.winfo_rootx() + (root.winfo_width() - dlg.winfo_reqwidth()) // 2
    y = root.winfo_rooty() + 60
    dlg.geometry(f"+{max(x, 0)}+{max(y, 0)}")
    entries[0].focus_set()
    dlg.grab_set()
    root.wait_window(dlg)
    return result[0]


def _open_url(url: str) -> None:
    import webbrowser
    webbrowser.open(url)


def _open_path(path: Path) -> None:
    """Show a folder in the system file manager."""
    import os
    import subprocess
    if sys.platform == "win32":
        os.startfile(path)  # noqa: S606 - opening a local folder the app itself created
    elif sys.platform == "darwin":
        subprocess.run(["open", str(path)], check=False)  # noqa: S603, S607
    else:
        subprocess.run(["xdg-open", str(path)], check=False)  # noqa: S603, S607


def generate_from_settings(settings: Settings) -> str:
    """A password using whatever the generator screen was last set to."""
    if settings.gen_mode == "passphrase":
        return generate_passphrase(settings.gen_words, separator=settings.gen_separator)
    if settings.gen_mode == "pin":
        return generate_pin(settings.gen_pin_length)
    return generate_password(
        max(MIN_LENGTH, min(MAX_LENGTH, settings.gen_length)),
        lowercase=settings.gen_lower, uppercase=settings.gen_upper,
        digits=settings.gen_digits, symbols=settings.gen_symbols,
        exclude_ambiguous=settings.gen_exclude_ambiguous,
        full_symbols=settings.gen_full_symbols,
    )


# Physical key positions, so Ctrl+F still works with the Russian layout active.
_X11_KEYCODES = dict(zip(
    (38, 56, 54, 40, 26, 41, 42, 43, 31, 44, 45, 46, 58, 57, 32, 33, 24, 27, 39, 28, 30, 55,
     25, 53, 29, 52),
    "abcdefghijklmnopqrstuvwxyz", strict=True))


def latin_key(event: tk.Event) -> str:
    """The Latin letter on the pressed key, whatever keyboard layout is active."""
    keysym = event.keysym or ""
    if len(keysym) == 1 and keysym.isascii() and keysym.isalpha():
        return keysym.lower()
    if sys.platform == "win32" and 65 <= event.keycode <= 90:
        return chr(event.keycode).lower()  # Windows virtual-key codes are the letters
    if sys.platform.startswith("linux"):
        return _X11_KEYCODES.get(event.keycode, "")
    return ""


def _short(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def strength_text(password: str) -> tuple[str, float]:
    bits = estimate_entropy(password) if password else 0.0
    return (f"{strength_label(bits)} · {bits:.0f} бит" if password else ""), bits


SCREENS: list[type[Screen]] = [LockScreen, ListScreen, EditScreen, GeneratorScreen,
                               SettingsScreen, AuditScreen]


def run_app() -> None:
    enable_hidpi()
    try:
        root = tk.Tk()
    except tk.TclError as e:
        # No display, e.g. running over a bare SSH session with no X forwarding.
        print(f"Не удалось открыть окно: {e}", flush=True)
        print("Графическому интерфейсу нужен рабочий стол.", flush=True)
        raise SystemExit(1) from e
    App(root)
    root.mainloop()
