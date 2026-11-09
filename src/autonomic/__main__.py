"""Module entry point: ``python3 -m autonomic``.

Equivalent to ``python3 -m autonomic.main``; kept so that operators who read the
README can boot either form.
"""
from .main import main

if __name__ == "__main__":
    raise SystemExit(main())
