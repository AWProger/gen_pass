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
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from core import (
    MAX_LENGTH,
    MIN_LENGTH,
    Record,
    Settings,
    Vault,
    estimate_entropy,
    generate_passphrase,
    generate_password,
    generate_pin,
    normalize_totp_secret,
    strength_label,
    totp,
    totp_remaining,
)
from theme import PlaceholderEntry, StrengthBar, Theme, Toggle, enable_hidpi

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

    def lock(self) -> None:
        if self.vault is None:
            return
        self.vault = None
        self.show("lock")
        self.toast("Хранилище заблокировано")

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
        chosen = filedialog.askopenfilename(
            parent=self, title="Файл хранилища",
            initialdir=str(self.path().parent),
            filetypes=[("Хранилище", "*.awp"), ("Все файлы", "*.*")],
        ) or filedialog.asksaveasfilename(
            parent=self, title="Или новое хранилище", defaultextension=".awp",
            initialdir=str(self.path().parent), filetypes=[("Хранилище", "*.awp")],
            confirmoverwrite=False,
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
        self.search = PlaceholderEntry(top, self.theme, "Поиск  (Ctrl+F)", self.var_search)
        self.search.pack(side="left", fill="x", expand=True)
        self.var_search.trace_add("write", lambda *_: self.refresh())
        self.search.bind("<Down>", lambda _e: self._focus_list())
        self.search.bind("<Return>", lambda _e: self._enter_from_search())
        self.search.bind("<Escape>", lambda _e: self.var_search.set(""))
        self.toolbar = ttk.Frame(top)
        self.toolbar.pack(side="right", padx=(6, 0))
        self.add_tool("＋", "Новая запись (Ctrl+N)", lambda: self.app.show("edit"))
        self.btn_pin = self.add_tool("▣", "Поверх всех окон", self.toggle_pin)
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

        self.empty = ttk.Label(list_frame, style="CardMuted.TLabel", justify="center")

        self._build_card()

    def add_tool(self, text: str, tip: str, command) -> ttk.Button:
        btn = ttk.Button(self.toolbar, text=text, style="Icon.TButton", width=2,
                         command=command)
        btn.pack(side="left", padx=(2, 0))
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
            import webbrowser
            url = rec.url if "://" in rec.url else "https://" + rec.url
            webbrowser.open(url)

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
        Tooltip(gen, "Сгенерировать (настройки генератора)", self.theme)
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
            widget.bind("<Escape>", lambda _e: self.cancel())

    def on_show(self, record_id: str | None = None, password: str | None = None,
                **_kwargs) -> None:
        vault = self.app.vault
        if vault is None:
            self.app.show("lock")
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


def _short(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def strength_text(password: str) -> tuple[str, float]:
    bits = estimate_entropy(password) if password else 0.0
    return (f"{strength_label(bits)} · {bits:.0f} бит" if password else ""), bits


SCREENS: list[type[Screen]] = [LockScreen, ListScreen, EditScreen]


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
