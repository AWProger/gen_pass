"""
Entry point for the password generator.

Kept intentionally thin: argument handling and startup only. All behaviour lives
in core.py (generation, crypto, storage) and ui.py (interface), so both stay
testable without a window.

Also refuses to run against a bare SSH session with no display, because tkinter
cannot open a window there. That case used to produce a confusing traceback.
"""

import sys

from core import __version__
from ui import run_app


def main() -> int:
    if "--version" in sys.argv or "-V" in sys.argv:
        print(f"gen_pass {__version__}")
        return 0

    if "--help" in sys.argv or "-h" in sys.argv:
        print(f"""Генератор паролей {__version__}

  python main.py             открыть программу
  python main.py --version   показать версию
""")
        return 0

    if not _has_display():
        print(
            "Графический интерфейс требует рабочего стола.\n"
            "Это похоже на запуск на сервере без графики.\n\n"
            "Скачайте готовую версию для Windows и запустите .exe.",
            file=sys.stderr,
        )
        return 1

    run_app()
    return 0


def _has_display() -> bool:
    """True when tkinter can plausibly open a window."""
    import os
    if sys.platform == "win32" or sys.platform == "darwin":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


if __name__ == "__main__":
    raise SystemExit(main())
