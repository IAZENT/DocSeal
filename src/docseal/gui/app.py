"""GUI application entry point for DocSeal."""

import sys
from PyQt6.QtWidgets import QApplication
from docseal import __version__
from .main_window import MainWindow


def main() -> int:
    """Launch the GUI application."""
    app = QApplication(sys.argv)
    app.setApplicationName("DocSeal")
    app.setApplicationVersion(__version__)

    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
