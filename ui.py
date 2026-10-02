"""
ui.py - tkinter interface for the password vault.

Design decisions worth stating, because they are deliberate departures from the
original interface:

  * The vault is unlocked once at start and kept in memory. The original asked
    for nothing and silently held every password in a plain list with no vault
    file at all; this version refuses to save anything unless the user has
    actually created or unlocked a vault.

  * Every destructive action asks first. Clearing the history or deleting the
    vault file is not undoable, and the original did both on a single click with
    no confirmation.

  * Generated passwords are shown but never written to the vault automatically.
    Saving is an explicit action, because the original appended every generated
    password to history silently - generate ten passwords while experimenting
    and you have ten saved records.

  * The vault password is entered into a masked field, never a plain Entry.

  * Copy to clipboard is explicit, and the clipboard is cleared after a delay so
    the password does not sit in it indefinitely.

  * Errors go to messageboxes with the real message. The original swallowed
    import failures behind a bare "Ошибка".
"""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from typing import Callable

from core import (
    DEFAULT_DIR,
    MAX_LENGTH,
    MIN_LENGTH,
    Record,
    Vault,
    __version__,
    estimate_entropy,
    export_encrypted,
    export_plaintext,
    generate_password,
    strength_label,
)

APP_TITLE = "Генератор паролей"
CLIPBOARD_TTL_MS = 30_000  # clear the clipboard after this long


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"{APP_TITLE} {__version__}")
        self.root.geometry("720x640")
        self.root.minsize(640, 600)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.vault: Vault | None = None
        self._clipboard_job: str | None = None
        # Set only when the user overrides the default vault location.
        self._path_override: Path | None = None

        self._build_styles()
        self._build_vars()
        self._build_widgets()
        self._refresh_history()
        self._sync_controls()

    # ------------------------------------------------------------------
    # construction
    # ------------------------------------------------------------------

    def _build_styles(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass  # theme unavailable, default is fine

        style.configure("Title.TLabel", font=("Segoe UI", 15, "bold"))
        style.configure("Hint.TLabel", foreground="#666")
        style.configure("Result.TEntry", font=("Consolas", 14))
        style.configure("Strong.TLabel", foreground="#1a7f37", font=("Segoe UI", 10, "bold"))
        style.configure("Medium.TLabel", foreground="#9a6700", font=("Segoe UI", 10, "bold"))
        style.configure("Weak.TLabel", foreground="#cf222e", font=("Segoe UI", 10, "bold"))

    def _build_vars(self) -> None:
        self.var_length = tk.IntVar(value=20)
        self.var_lower = tk.BooleanVar(value=True)
        self.var_upper = tk.BooleanVar(value=True)
        self.var_digits = tk.BooleanVar(value=True)
        self.var_symbols = tk.BooleanVar(value=True)
        self.var_full_symbols = tk.BooleanVar(value=False)
        self.var_exclude_ambiguous = tk.BooleanVar(value=False)

        self.var_site = tk.StringVar()
        self.var_login = tk.StringVar()
        self.var_email = tk.StringVar()
        self.var_note = tk.StringVar()

        self.var_password = tk.StringVar()
        self.var_strength = tk.StringVar(value="—")
        self.var_entropy = tk.StringVar()
        self.var_status = tk.StringVar(value="Хранилище не открыто")
        self.var_search = tk.StringVar()
        self.var_mask = tk.BooleanVar(value=True)
        self.var_master = tk.StringVar()

    def _build_widgets(self) -> None:
        pad = {"padx": 10, "pady": 6}

        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text=APP_TITLE, style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text="Пароли генерируются локально и никуда не отправляются",
            style="Hint.TLabel",
        ).pack(anchor="w", pady=(0, 10))

        self._build_generator(outer, pad)
        self._build_credentials(outer, pad)
        self._build_vault_bar(outer, pad)
        self._build_history(outer, pad)
        self._build_status(outer, pad)

    def _build_generator(self, parent, pad) -> None:
        box = ttk.LabelFrame(parent, text="Генерация", padding=10)
        box.pack(fill="x", pady=pad["pady"])
        box.columnconfigure(1, weight=1)

        ttk.Label(box, text="Длина").grid(row=0, column=0, sticky="w")
        self.scale = ttk.Scale(
            box,
            from_=MIN_LENGTH,
            to=64,
            orient="horizontal",
            variable=self.var_length,
            command=self._on_length_change,
        )
        self.scale.grid(row=0, column=1, sticky="ew", padx=8)
        self.lbl_length = ttk.Label(box, text=str(self.var_length.get()), width=4)
        self.lbl_length.grid(row=0, column=2)

        checks = ttk.Frame(box)
        checks.grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Checkbutton(checks, text="a-z", variable=self.var_lower,
                        command=self._sync_controls).pack(side="left")
        ttk.Checkbutton(checks, text="A-Z", variable=self.var_upper,
                        command=self._sync_controls).pack(side="left", padx=6)
        ttk.Checkbutton(checks, text="0-9", variable=self.var_digits,
                        command=self._sync_controls).pack(side="left")
        ttk.Checkbutton(checks, text="Символы", variable=self.var_symbols,
                        command=self._sync_controls).pack(side="left", padx=6)
        ttk.Checkbutton(checks, text="Убрать похожие (I l 1 O 0)",
                        variable=self.var_exclude_ambiguous,
                        command=self._sync_controls).pack(side="left", padx=6)

        ttk.Checkbutton(box, text="Полный набор символов (включая кавычки и \\)",
                        variable=self.var_full_symbols,
                        command=self._sync_controls).grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))

        out = ttk.Frame(box)
        out.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(10, 0))
        out.columnconfigure(0, weight=1)

        self.entry_result = ttk.Entry(out, textvariable=self.var_password,
                                      font=("Consolas", 14))
        self.entry_result.grid(row=0, column=0, sticky="ew")

        ttk.Button(out, text="Сгенерировать", command=self.on_generate).grid(
            row=0, column=1, padx=(8, 0))
        ttk.Button(out, text="Копировать", command=self.on_copy).grid(
            row=0, column=2, padx=(4, 0))

        info = ttk.Frame(box)
        info.grid(row=4, column=0, columnspan=3, sticky="w", pady=(8, 0))
        self.lbl_strength = ttk.Label(info, textvariable=self.var_strength)
        self.lbl_strength.pack(side="left")
        ttk.Label(info, textvariable=self.var_entropy, style="Hint.TLabel").pack(
            side="left", padx=10)

    def _build_credentials(self, parent, pad) -> None:
        box = ttk.LabelFrame(parent, text="Данные записи", padding=10)
        box.pack(fill="x", pady=pad["pady"])
        box.columnconfigure(1, weight=1)

        rows = [("Сайт", self.var_site), ("Логин", self.var_login),
                ("E-mail", self.var_email), ("Заметка", self.var_note)]
        for i, (label, var) in enumerate(rows):
            ttk.Label(box, text=label).grid(row=i, column=0, sticky="w", pady=3)
            entry = ttk.Entry(box, textvariable=var)
            entry.grid(row=i, column=1, sticky="ew", padx=8, pady=3)
            if label == "Заметка":
                entry.grid(row=i, column=0, columnspan=2, sticky="ew", padx=8, pady=3)
            self._mask_entries = getattr(self, "_mask_entries", {})
            self._mask_entries[label] = entry

        ttk.Button(box, text="Сохранить в хранилище", command=self.on_save).grid(
            row=len(rows), column=0, columnspan=2, sticky="w", pady=(8, 0))

    def _build_vault_bar(self, parent, pad) -> None:
        box = ttk.LabelFrame(parent, text="Хранилище", padding=10)
        box.pack(fill="x", pady=pad["pady"])

        self.lbl_path = ttk.Label(box, text=f"Файл: {DEFAULT_DIR / 'vault.awp'}",
                                  style="Hint.TLabel")
        self.lbl_path.pack(anchor="w")

        row = ttk.Frame(box)
        row.pack(fill="x", pady=(8, 0))

        ttk.Label(row, text="Мастер-пароль").pack(side="left")
        self.entry_master = ttk.Entry(row, textvariable=self.var_master,
                                      show="•", width=22)
        self.entry_master.pack(side="left", padx=8)
        ttk.Checkbutton(row, text="Показать", variable=self.var_mask,
                        command=self._toggle_master).pack(side="left")

        buttons = ttk.Frame(box)
        buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(buttons, text="Создать", command=self.on_create).pack(side="left")
        ttk.Button(buttons, text="Открыть", command=self.on_unlock).pack(side="left", padx=6)
        ttk.Button(buttons, text="Заблокировать", command=self.on_lock).pack(side="left")
        ttk.Button(buttons, text="Сменить путь", command=self.on_change_path).pack(side="left", padx=6)

        row2 = ttk.Frame(box)
        row2.pack(fill="x", pady=(6, 0))
        ttk.Button(row2, text="Экспорт (зашифрованный)",
                   command=lambda: self.on_export(encrypted=True)).pack(side="left")
        ttk.Button(row2, text="Экспорт (открытый)",
                   command=lambda: self.on_export(encrypted=False)).pack(side="left", padx=6)
        ttk.Button(row2, text="Импорт", command=self.on_import).pack(side="left")
        ttk.Button(row2, text="Удалить файл", command=self.on_delete_vault).pack(side="left", padx=6)

    def _build_history(self, parent, pad) -> None:
        box = ttk.LabelFrame(parent, text="История", padding=10)
        box.pack(fill="both", expand=True, pady=pad["pady"])
        box.columnconfigure(0, weight=1)
        box.rowconfigure(1, weight=1)

        top = ttk.Frame(box)
        top.grid(row=0, column=0, sticky="ew")
        ttk.Label(top, text="Поиск").pack(side="left")
        self.entry_search = ttk.Entry(top, textvariable=self.var_search, width=30)
        self.entry_search.pack(side="left", padx=6)
        self.entry_search.bind("<Return>", lambda _e: self._refresh_history())
        self.entry_search.bind("<KeyRelease>", lambda _e: self._refresh_history())
        ttk.Button(top, text="Найти", command=self._refresh_history).pack(side="left")
        ttk.Button(top, text="Очистить поиск", command=self._clear_search).pack(side="left", padx=6)
        ttk.Button(top, text="Удалить выбранное", command=self.on_delete_record).pack(side="left")

        cols = ("site", "login", "email", "created", "strength", "id")
        self.tree = ttk.Treeview(box, columns=cols, show="headings", selectmode="browse")
        headings = {
            "site": ("Сайт", 150), "login": ("Логин", 130), "email": ("E-mail", 150),
            "created": ("Создан", 130), "strength": ("Стойкость", 100), "id": ("ID", 0),
        }
        for col, (text, width) in headings.items():
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, stretch=(col in ("site", "login", "email")))
        self.tree.column("id", width=0, stretch=False)
        self.tree.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        self.tree.bind("<Delete>", lambda _e: self.on_delete_record())

        sb = ttk.Scrollbar(box, orient="vertical", command=self.tree.yview)
        sb.grid(row=1, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=sb.set)

        btns = ttk.Frame(box)
        btns.grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Button(btns, text="Показать пароль", command=self.on_reveal).pack(side="left")
        ttk.Button(btns, text="Копировать пароль", command=self.on_copy_selected).pack(side="left", padx=6)
        ttk.Button(btns, text="Очистить историю", command=self.on_clear_history).pack(side="left")
        ttk.Label(btns, text="  ↑↓ выбрать, Delete — удалить",
                  style="Hint.TLabel").pack(side="left", padx=10)

    def _build_status(self, parent, pad) -> None:
        ttk.Label(parent, textvariable=self.var_status, style="Hint.TLabel").pack(
            anchor="w", pady=(4, 0))

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _on_length_change(self, _value) -> None:
        self.var_length.set(int(float(_value)))
        self.lbl_length.config(text=str(self.var_length.get()))

    def _sync_controls(self) -> None:
        """Disable symbol options that cannot apply, and warn when no class is on."""
        sym_on = self.var_symbols.get()
        self.entry_master.config(show="•" if self.var_mask.get() else "")

        any_class = any((self.var_lower.get(), self.var_upper.get(),
                         self.var_digits.get(), self.var_symbols.get()))
        if not any_class:
            self.var_status.set("Выберите хотя бы один набор символов")

    def _toggle_master(self) -> None:
        self._sync_controls()

    def _require_vault(self) -> Vault | None:
        if self.vault is None:
            messagebox.showinfo(
                APP_TITLE,
                "Сначала откройте хранилище: «Создать» для нового или «Открыть» для существующего.",
            )
            return None
        return self.vault

    def _refresh_history(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        if self.vault is None:
            self.var_status.set("Хранилище не открыто")
            return

        records = self.vault.search(self.var_search.get()) if self.var_search.get() \
            else self.vault.all()

        for rec in records:
            bits = estimate_entropy(rec.password)
            self.tree.insert(
                "", "end",
                values=(rec.site, rec.login, rec.email, rec.created,
                        strength_label(bits), rec.id),
            )
        self.var_status.set(f"Записей: {len(records)}   файл: {self.vault.path}")

    def _clear_search(self) -> None:
        self.var_search.set("")
        self._refresh_history()

    def _selected(self) -> Record | None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo(APP_TITLE, "Сначала выберите запись в таблице.")
            return None
        if self.vault is None:
            return None
        return self.vault.get(self.tree.item(sel[0], "values")[-1])

    # ------------------------------------------------------------------
    # actions
    # ------------------------------------------------------------------

    def on_generate(self) -> None:
        try:
            pwd = generate_password(
                self.var_length.get(),
                lowercase=self.var_lower.get(),
                uppercase=self.var_upper.get(),
                digits=self.var_digits.get(),
                symbols=self.var_symbols.get(),
                exclude_ambiguous=self.var_exclude_ambiguous.get(),
                full_symbols=self.var_full_symbols.get(),
            )
        except ValueError as e:
            messagebox.showerror(APP_TITLE, str(e))
            return

        self.var_password.set(pwd)
        bits = estimate_entropy(pwd)
        self.var_entropy.set(f"{bits:.0f} бит энтропии")
        label = strength_label(bits)
        self.var_strength.set(label)
        style = {"Очень слабый": "Weak", "Слабый": "Weak",
                 "Средний": "Medium", "Сильный": "Strong", "Очень сильный": "Strong"}[label]
        self.lbl_strength.config(style=f"{style}.TLabel")

    def on_copy(self) -> None:
        pwd = self.var_password.get()
        if not pwd:
            messagebox.showinfo(APP_TITLE, "Сначала сгенерируйте пароль.")
            return
        self._copy_with_ttl(pwd)

    def _copy_with_ttl(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()

        if self._clipboard_job:
            self.root.after_cancel(self._clipboard_job)
        self._clipboard_job = self.root.after(
            CLIPBOARD_TTL_MS, lambda: (self.root.clipboard_clear(),
                                       self.var_status.set("Буфер обмена очищен")),
        )
        self.var_status.set("Скопировано. Буфер будет очищен через 30 секунд.")

    def on_save(self) -> None:
        vault = self._require_vault()
        if vault is None:
            return
        pwd = self.var_password.get()
        if not pwd:
            messagebox.showinfo(APP_TITLE, "Сначала сгенерируйте пароль.")
            return
        try:
            rec = vault.add(pwd, self.var_site.get().strip(),
                            self.var_login.get().strip(),
                            self.var_email.get().strip(),
                            self.var_note.get().strip())
            vault.save()
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Не удалось сохранить: {e}")
            return

        self.var_status.set(f"Сохранено: {rec.site or 'без названия'}")
        for var in (self.var_site, self.var_login, self.var_email, self.var_note):
            var.set("")
        self._refresh_history()

    def on_create(self) -> None:
        master = self.var_master.get()
        if not master:
            messagebox.showwarning(APP_TITLE, "Введите мастер-пароль.")
            return
        if master != master.strip():
            messagebox.showwarning(
                APP_TITLE,
                "Пароль содержит пробелы в начале или конце.\n"
                "Уберите их — иначе при открытии придётся вводить точно так же.")
            return
        if len(master) < 8:
            messagebox.showwarning(
                APP_TITLE,
                "Мастер-пароль короче 8 символов. Он защищает всё хранилище целиком — "
                "выберите что-то надёжнее.")
            return

        try:
            self.vault = Vault(self._current_path())
            self.vault.create(master)
        except FileExistsError as e:
            messagebox.showwarning(APP_TITLE, str(e))
            return
        except (OSError, ValueError) as e:
            messagebox.showerror(APP_TITLE, f"Не удалось создать: {e}")
            return

        self._update_path_label()
        self._refresh_history()
        self.var_status.set("Хранилище создано")

    def on_unlock(self) -> None:
        master = self.var_master.get()
        if not master:
            messagebox.showwarning(APP_TITLE, "Введите мастер-пароль.")
            return

        vault = Vault(self._current_path())
        if not vault.exists():
            messagebox.showinfo(APP_TITLE, "Файл хранилища не найден. Создайте новый.")
            return
        try:
            vault.unlock(master)
        except (ValueError, FileNotFoundError) as e:
            messagebox.showerror(APP_TITLE, f"Не удалось открыть: {e}")
            return

        self.vault = vault
        self._update_path_label()
        self._refresh_history()
        self.var_status.set("Хранилище открыто")

    def on_lock(self) -> None:
        if self.vault is None:
            return
        self.vault = None
        self.var_master.set("")
        self._clear_search()
        self._refresh_history()
        self.var_status.set("Хранилище заблокировано")

    def on_change_path(self) -> None:
        chosen = filedialog.asksaveasfilename(
            title="Куда сохранять хранилище",
            defaultextension=".awp",
            initialdir=str(self._current_path().parent),
            initialfile=self._current_path().name,
        )
        if not chosen:
            return
        self._path_override = Path(chosen)
        self._update_path_label()
        if self.vault is not None:
            self.vault.path = self._path_override
            self._refresh_history()

    def _current_path(self) -> Path:
        return getattr(self, "_path_override", None) or (DEFAULT_DIR / "vault.awp")

    def _update_path_label(self) -> None:
        self.lbl_path.config(text=f"Файл: {self._current_path()}")

    def on_export(self, encrypted: bool) -> None:
        vault = self._require_vault()
        if vault is None:
            return
        if not vault.all():
            messagebox.showinfo(APP_TITLE, "Нечего экспортировать: хранилище пусто.")
            return

        kind = "зашифрованный" if encrypted else "открытый"
        chosen = filedialog.asksaveasfilename(
            title=f"Экспорт ({kind})",
            defaultextension=".awpe" if encrypted else ".json",
            filetypes=[("Файл", "*.*")],
        )
        if not chosen:
            return

        try:
            if encrypted:
                master = self.var_master.get()
                if not master:
                    messagebox.showwarning(
                        APP_TITLE,
                        "Для зашифрованного экспорта нужен мастер-пароль.")
                    return
                export_encrypted(vault.all(), chosen, master)
            else:
                if not messagebox.askyesno(
                    APP_TITLE,
                    "Открытый экспорт записывает пароли обычным текстом.\n\n"
                    "Любой, кто прочитает файл, увидит все пароли.\n\n"
                    "Продолжить?",
                ):
                    return
                export_plaintext(vault.all(), chosen)
        except (OSError, ValueError) as e:
            messagebox.showerror(APP_TITLE, f"Ошибка экспорта: {e}")
            return

        self.var_status.set(f"Экспортировано: {chosen}")

    def on_import(self) -> None:
        chosen = filedialog.askopenfilename(
            title="Импорт из зашифрованного экспорта", filetypes=[("Файл", "*.*")]
        )
        if not chosen:
            return
        master = self.var_master.get()
        if not master:
            messagebox.showwarning(APP_TITLE, "Введите мастер-пароль от файла.")
            return

        try:
            from core import import_encrypted
            records = import_encrypted(chosen, master)
        except (ValueError, OSError) as e:
            messagebox.showerror(APP_TITLE, f"Импорт не удался: {e}")
            return

        vault = self._require_vault()
        if vault is None:
            messagebox.showinfo(
                APP_TITLE,
                f"Прочитано записей: {len(records)}.\n"
                "Откройте хранилище, чтобы импортировать в него.")
            return

        if not messagebox.askyesno(
            APP_TITLE,
            f"Импортировать {len(records)} записей в текущее хранилище?\n"
            "Существующие записи останутся.",
        ):
            return

        for rec in records:
            vault.records.append(rec)
        try:
            vault.save()
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Не удалось сохранить: {e}")
            return

        self._refresh_history()
        self.var_status.set(f"Импортировано записей: {len(records)}")

    def on_delete_vault(self) -> None:
        vault = self._require_vault()
        if vault is None:
            return
        if not messagebox.askyesno(
            APP_TITLE,
            f"Удалить файл хранилища?\n\n{vault.path}\n\n"
            "Все пароли будут потеряны безвозвратно.",
        ):
            return
        try:
            vault.path.unlink(missing_ok=True)
            salt = vault.path.with_suffix(".salt")
            salt.unlink(missing_ok=True)
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Не удалось удалить: {e}")
            return

        self.vault = None
        self._refresh_history()
        self.var_status.set("Файл хранилища удалён")

    def on_reveal(self) -> None:
        rec = self._selected()
        if rec is None:
            return
        messagebox.showinfo(APP_TITLE, f"Пароль:\n\n{rec.password}")

    def on_copy_selected(self) -> None:
        rec = self._selected()
        if rec is None:
            return
        self._copy_with_ttl(rec.password)

    def on_delete_record(self) -> None:
        rec = self._selected()
        if rec is None:
            return
        if not messagebox.askyesno(
            APP_TITLE, f"Удалить запись для «{rec.site or 'без названия'}»?"
        ):
            return

        vault = self.vault
        vault.delete(rec.id)
        try:
            vault.save()
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Не удалось сохранить: {e}")
            return
        self._refresh_history()
        self.var_status.set("Запись удалена")

    def on_clear_history(self) -> None:
        vault = self._require_vault()
        if vault is None:
            return
        if not vault.all():
            messagebox.showinfo(APP_TITLE, "Хранилище и так пустое.")
            return
        if not messagebox.askyesno(
            APP_TITLE,
            f"Удалить все {len(vault.all())} записей?\n\n"
            "Отменить это будет нельзя.",
        ):
            return

        vault.clear()
        try:
            vault.save()
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Не удалось сохранить: {e}")
            return
        self._refresh_history()
        self.var_status.set("История очищена")

    def on_close(self) -> None:
        if self._clipboard_job:
            try:
                self.root.after_cancel(self._clipboard_job)
            except tk.TclError:
                pass
        try:
            self.root.clipboard_clear()
        except tk.TclError:
            pass
        self.root.destroy()


def run_app() -> None:
    root = tk.Tk()
    try:
        App(root)
        root.mainloop()
    except tk.TclError as e:
        # No display, e.g. running over a bare SSH session with no X forwarding.
        print(f"Не удалось открыть окно: {e}", flush=True)
        print("Графическому интерфейсу нужен запущенный на ПК, не на сервере.", flush=True)
        raise SystemExit(1)