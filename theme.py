"""
theme.py - colours, fonts and small custom widgets for the interface.

Kept apart from ui.py so the screens describe *what* is shown and this module
decides *how it looks*. Only tkinter/ttk, no third-party theming packages: the
"clam" theme is the one ttk theme whose colours can be fully overridden on every
platform, so everything is built on top of it.
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

PALETTES: dict[str, dict[str, str]] = {
    "dark": {
        "bg": "#16181d",
        "surface": "#1f2229",
        "surface2": "#292d36",
        "border": "#343944",
        "fg": "#e6e8ec",
        "muted": "#8b919c",
        "accent": "#5b8cff",
        "accent_hover": "#7aa2ff",
        "accent_fg": "#ffffff",
        "select": "#2f4a86",
        "danger": "#ff6b6b",
        "warn": "#f2b84b",
        "ok": "#4cc38a",
    },
    "light": {
        "bg": "#f4f5f7",
        "surface": "#ffffff",
        "surface2": "#eceef2",
        "border": "#d5d9e0",
        "fg": "#1d2129",
        "muted": "#6b7280",
        "accent": "#3366ff",
        "accent_hover": "#1f4fe0",
        "accent_fg": "#ffffff",
        "select": "#d6e2ff",
        "danger": "#d93636",
        "warn": "#b7791f",
        "ok": "#1f9d61",
    },
}


def _pick_family(root: tk.Misc, candidates: tuple[str, ...], fallback: str) -> str:
    available = {f.lower() for f in tkfont.families(root)}
    for name in candidates:
        if name.lower() in available:
            return name
    return fallback


class Theme:
    """Applies a palette to ttk styles and remembers it for plain tk widgets."""

    def __init__(self, root: tk.Tk, name: str = "dark") -> None:
        self.root = root
        self.style = ttk.Style(root)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        ui = _pick_family(root, ("Segoe UI", "SF Pro Text", "Inter", "Ubuntu",
                                 "Cantarell", "DejaVu Sans"), "TkDefaultFont")
        mono = _pick_family(root, ("Cascadia Mono", "Consolas", "JetBrains Mono",
                                   "SF Mono", "Menlo", "DejaVu Sans Mono"), "TkFixedFont")
        self.font = (ui, 10)
        self.font_small = (ui, 9)
        self.font_bold = (ui, 10, "bold")
        self.font_title = (ui, 14, "bold")
        self.font_icon = (ui, 12)
        self.mono = (mono, 13)
        self.mono_big = (mono, 15)
        self.mono_small = (mono, 10)
        self.name = ""
        self.c: dict[str, str] = {}
        self.apply(name)

    def apply(self, name: str) -> None:
        self.name = name if name in PALETTES else "dark"
        c = self.c = PALETTES[self.name]
        s = self.style
        self.root.configure(bg=c["bg"])
        self.root.option_add("*Font", self.font)
        self.root.option_add("*Menu.background", c["surface"])
        self.root.option_add("*Menu.foreground", c["fg"])
        self.root.option_add("*Menu.activeBackground", c["select"])
        self.root.option_add("*Menu.activeForeground", c["fg"])
        self.root.option_add("*Menu.relief", "flat")
        self.root.option_add("*TCombobox*Listbox.background", c["surface"])
        self.root.option_add("*TCombobox*Listbox.foreground", c["fg"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", c["select"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", c["fg"])

        s.configure(".", background=c["bg"], foreground=c["fg"], font=self.font,
                    bordercolor=c["border"], lightcolor=c["border"], darkcolor=c["border"],
                    troughcolor=c["surface2"], focuscolor=c["accent"],
                    selectbackground=c["select"], selectforeground=c["fg"],
                    fieldbackground=c["surface"], insertcolor=c["fg"])
        s.configure("TFrame", background=c["bg"])
        s.configure("Card.TFrame", background=c["surface"])
        s.configure("TLabel", background=c["bg"], foreground=c["fg"])
        s.configure("Card.TLabel", background=c["surface"])
        s.configure("Muted.TLabel", foreground=c["muted"], font=self.font_small)
        s.configure("CardMuted.TLabel", background=c["surface"], foreground=c["muted"],
                    font=self.font_small)
        s.configure("Title.TLabel", font=self.font_title)
        s.configure("Bold.TLabel", font=self.font_bold)
        s.configure("Mono.TLabel", background=c["surface"], font=self.mono)
        s.configure("MonoBig.TLabel", background=c["surface"], font=self.mono_big)
        s.configure("Danger.TLabel", foreground=c["danger"])
        s.configure("Ok.TLabel", foreground=c["ok"])
        s.configure("Warn.TLabel", foreground=c["warn"])

        button = {"padding": (10, 5), "relief": "flat", "borderwidth": 1}
        s.configure("TButton", background=c["surface2"], foreground=c["fg"],
                    bordercolor=c["border"], **button)
        s.map("TButton",
              background=[("disabled", c["surface"]), ("pressed", c["border"]),
                          ("active", c["border"])],
              foreground=[("disabled", c["muted"])])
        s.configure("Accent.TButton", background=c["accent"], foreground=c["accent_fg"],
                    bordercolor=c["accent"], font=self.font_bold, **button)
        s.map("Accent.TButton",
              background=[("pressed", c["accent_hover"]), ("active", c["accent_hover"])])
        s.configure("Danger.TButton", background=c["surface2"], foreground=c["danger"],
                    bordercolor=c["border"], **button)
        s.map("Danger.TButton", background=[("active", c["border"])])
        # Square icon buttons for the toolbar.
        s.configure("Icon.TButton", background=c["bg"], foreground=c["fg"],
                    bordercolor=c["bg"], padding=(4, 3), relief="flat", font=self.font_icon)
        s.map("Icon.TButton", background=[("pressed", c["border"]), ("active", c["surface2"])],
              bordercolor=[("active", c["surface2"])])
        s.configure("IconOn.TButton", background=c["select"], foreground=c["fg"],
                    bordercolor=c["select"], padding=(4, 3), relief="flat", font=self.font_icon)
        s.map("IconOn.TButton", background=[("active", c["select"])])
        s.configure("Star.TButton", background=c["bg"], foreground=c["warn"],
                    bordercolor=c["bg"], padding=(6, 3), relief="flat", font=self.font_icon)
        s.configure("CardIcon.TButton", background=c["surface"], foreground=c["fg"],
                    bordercolor=c["surface"], padding=(5, 1), relief="flat", font=self.font)
        s.map("CardIcon.TButton", background=[("active", c["surface2"])],
              bordercolor=[("active", c["surface2"])])
        s.configure("CardIconOn.TButton", background=c["select"], foreground=c["fg"],
                    bordercolor=c["select"], padding=(5, 1), relief="flat", font=self.font)
        s.configure("Link.TButton", background=c["bg"], foreground=c["accent"],
                    bordercolor=c["bg"], padding=(2, 0), relief="flat", font=self.font_small)
        s.configure("Warn.TButton", background=c["bg"], foreground=c["warn"],
                    bordercolor=c["bg"], padding=(2, 0), relief="flat", font=self.font_small)
        s.map("Link.TButton", background=[("active", c["bg"])],
              foreground=[("active", c["accent_hover"])])

        s.configure("TEntry", fieldbackground=c["surface"], foreground=c["fg"],
                    bordercolor=c["border"], lightcolor=c["border"], darkcolor=c["border"],
                    padding=(6, 5), insertcolor=c["fg"])
        s.map("TEntry", bordercolor=[("focus", c["accent"])],
              lightcolor=[("focus", c["accent"])])
        s.configure("Mono.TEntry", padding=(6, 5))
        s.configure("TCombobox", fieldbackground=c["surface"], background=c["surface2"],
                    foreground=c["fg"], arrowcolor=c["fg"], bordercolor=c["border"],
                    padding=(6, 4))
        s.map("TCombobox", fieldbackground=[("readonly", c["surface"])],
              foreground=[("readonly", c["fg"])],
              selectbackground=[("readonly", c["surface"])],
              selectforeground=[("readonly", c["fg"])],
              bordercolor=[("focus", c["accent"])])
        s.configure("TSpinbox", fieldbackground=c["surface"], background=c["surface2"],
                    foreground=c["fg"], arrowcolor=c["fg"], bordercolor=c["border"],
                    padding=(6, 4))

        check = {"background": c["bg"], "foreground": c["fg"], "indicatorbackground": c["surface"],
                 "indicatorforeground": c["fg"], "focuscolor": c["bg"]}
        s.configure("TCheckbutton", indicatorrelief="flat", indicatormargin=(0, 0, 6, 0),
                    **check)
        s.map("TCheckbutton", background=[("active", c["bg"])],
              indicatorbackground=[("selected", c["accent"]), ("active", c["surface2"])],
              indicatorforeground=[("selected", c["accent_fg"])])
        s.configure("TRadiobutton", **check)
        s.map("TRadiobutton", background=[("active", c["bg"])],
              indicatorbackground=[("selected", c["accent"]), ("active", c["surface2"])])
        # Segmented control: radio buttons drawn as toggle buttons.
        s.configure("Segment.TRadiobutton", background=c["surface2"], foreground=c["muted"],
                    padding=(10, 4), anchor="center", indicatorsize=0, borderwidth=0,
                    indicatormargin=0, indicatorrelief="flat")
        s.layout("Segment.TRadiobutton",
                 [("Radiobutton.padding", {"sticky": "nswe", "children": [
                     ("Radiobutton.label", {"sticky": "nswe"})]})])
        s.map("Segment.TRadiobutton",
              background=[("selected", c["accent"]), ("active", c["border"])],
              foreground=[("selected", c["accent_fg"]), ("active", c["fg"])])

        s.configure("Horizontal.TScale", background=c["accent"], troughcolor=c["surface2"],
                    bordercolor=c["bg"], lightcolor=c["accent"], darkcolor=c["accent"])
        s.configure("Vertical.TScrollbar", background=c["surface2"], troughcolor=c["bg"],
                    bordercolor=c["bg"], arrowcolor=c["muted"], lightcolor=c["surface2"],
                    darkcolor=c["surface2"], gripcount=0, arrowsize=10)
        s.map("Vertical.TScrollbar", background=[("active", c["border"])])
        s.configure("TSeparator", background=c["border"])

        s.configure("Treeview", background=c["surface"], fieldbackground=c["surface"],
                    foreground=c["fg"], bordercolor=c["border"], rowheight=30,
                    font=self.font, borderwidth=0, relief="flat")
        s.map("Treeview", background=[("selected", c["select"])],
              foreground=[("selected", c["fg"])])
        s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        s.configure("Treeview.Heading", background=c["surface2"], foreground=c["muted"])

    def text_widget_options(self) -> dict[str, object]:
        """Colours for plain tk.Text, which ttk styles do not reach."""
        c = self.c
        return {"bg": c["surface"], "fg": c["fg"], "insertbackground": c["fg"],
                "selectbackground": c["select"], "selectforeground": c["fg"],
                "highlightthickness": 1, "highlightbackground": c["border"],
                "highlightcolor": c["accent"], "relief": "flat", "borderwidth": 0,
                "font": self.font, "padx": 6, "pady": 4}

    def strength_color(self, bits: float) -> str:
        if bits < 60:
            return self.c["danger"]
        if bits < 80:
            return self.c["warn"]
        return self.c["ok"]


class StrengthBar(tk.Canvas):
    """A thin coloured bar: 0 bits empty, 128+ bits full."""

    def __init__(self, master: tk.Misc, theme: Theme, height: int = 4) -> None:
        super().__init__(master, height=height, highlightthickness=0, bd=0,
                         bg=theme.c["surface2"])
        self.theme = theme
        self._bits = 0.0
        self.bind("<Configure>", lambda _e: self._draw())

    def set(self, bits: float) -> None:
        self._bits = bits
        self._draw()

    def _draw(self) -> None:
        self.delete("all")
        self.configure(bg=self.theme.c["surface2"])
        width = self.winfo_width()
        filled = int(width * min(self._bits, 128) / 128)
        if filled > 0:
            self.create_rectangle(0, 0, filled, int(self["height"]),
                                  fill=self.theme.strength_color(self._bits), width=0)


class PlaceholderEntry(ttk.Entry):
    """Entry that shows grey hint text while it is empty and unfocused."""

    def __init__(self, master: tk.Misc, theme: Theme, placeholder: str,
                 textvariable: tk.StringVar, **kw) -> None:
        super().__init__(master, textvariable=textvariable, **kw)
        self.theme = theme
        self.var = textvariable
        self.hint = tk.Label(self, text=placeholder, fg=theme.c["muted"],
                             bg=theme.c["surface"], font=theme.font, cursor="xterm")
        self.hint.bind("<Button-1>", lambda _e: self.focus_set())
        self.var.trace_add("write", lambda *_: self._update())
        self.bind("<FocusIn>", lambda _e: self._update(), add="+")
        self.bind("<FocusOut>", lambda _e: self._update(), add="+")
        self._update()

    def _update(self) -> None:
        if self.var.get():
            self.hint.place_forget()
        else:
            self.hint.configure(fg=self.theme.c["muted"], bg=self.theme.c["surface"])
            self.hint.place(x=7, rely=0.5, anchor="w")


def enable_hidpi() -> None:
    """Crisp text on scaled Windows displays instead of blurry bitmap scaling."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass


class Toggle(ttk.Button):
    """Icon button bound to a BooleanVar: highlighted while the value is true."""

    def __init__(self, master: tk.Misc, variable: tk.BooleanVar, text_on: str,
                 text_off: str | None = None, command=None, card: bool = False, **kw) -> None:
        self.var = variable
        self.text_on, self.text_off = text_on, text_off or text_on
        self.card = card
        self.user_command = command
        super().__init__(master, command=self._flip, width=kw.pop("width", 2), **kw)
        variable.trace_add("write", lambda *_: self.sync())
        self.sync()

    def _flip(self) -> None:
        self.var.set(not self.var.get())
        if self.user_command:
            self.user_command()

    def sync(self) -> None:
        on = self.var.get()
        if self.card:
            style = "CardIconOn.TButton" if on else "CardIcon.TButton"
        else:
            style = "IconOn.TButton" if on else "Icon.TButton"
        self.configure(text=self.text_on if on else self.text_off, style=style)


class ScrollFrame(ttk.Frame):
    """A vertically scrolling container; put children into `.inner`."""

    def __init__(self, master: tk.Misc, theme: Theme) -> None:
        super().__init__(master)
        self.canvas = tk.Canvas(self, highlightthickness=0, bd=0, bg=theme.c["bg"])
        self.bar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = ttk.Frame(self.canvas)
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.bar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.bar.pack(side="right", fill="y")
        self.inner.bind("<Configure>", lambda _e: self._sync())
        self.canvas.bind("<Configure>", lambda e: (
            self.canvas.itemconfigure(self._win, width=e.width), self._sync()))
        self.bind("<Enter>", lambda _e: self._wheel(True))
        self.bind("<Leave>", lambda _e: self._wheel(False))

    def _sync(self) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        fits = self.inner.winfo_reqheight() <= self.canvas.winfo_height()
        if fits:
            self.bar.pack_forget()
            self.canvas.yview_moveto(0)
        elif not self.bar.winfo_ismapped():
            self.bar.pack(side="right", fill="y")

    def _wheel(self, on: bool) -> None:
        if on:
            self.bind_all("<MouseWheel>", self._on_wheel)
            self.bind_all("<Button-4>", lambda _e: self._scroll(-1))
            self.bind_all("<Button-5>", lambda _e: self._scroll(1))
        else:
            self.unbind_all("<MouseWheel>")
            self.unbind_all("<Button-4>")
            self.unbind_all("<Button-5>")

    def _on_wheel(self, event: tk.Event) -> None:
        self._scroll(-1 if event.delta > 0 else 1)

    def _scroll(self, units: int) -> None:
        if self.bar.winfo_ismapped():
            self.canvas.yview_scroll(units * 2, "units")
