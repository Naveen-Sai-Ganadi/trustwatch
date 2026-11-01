"""Entry point for the frozen TrustWatch desktop app (PyInstaller runs this file).

It only hands over to trustwatch.desktop.main, so the frozen app and `trustwatch app` start the same way.
"""

from trustwatch.desktop import main

raise SystemExit(main())
