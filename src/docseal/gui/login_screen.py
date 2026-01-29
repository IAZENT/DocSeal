"""Login screen for DocSeal GUI."""

from typing import Callable
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QPixmap

from .auth import AuthenticationManager


class LoginScreen(QWidget):
    """Login screen widget."""

    def __init__(self, auth_manager: AuthenticationManager, 
                 on_success: Callable[[], None]) -> None:
        """
        Initialize the login screen.

        Args:
            auth_manager: Authentication manager
            on_success: Callback when login succeeds
        """
        super().__init__()
        self.auth_manager = auth_manager
        self.on_success = on_success
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the UI."""
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(20)

        # Main container
        container = QWidget()
        container.setMaximumWidth(400)
        container_layout = QVBoxLayout(container)
        container_layout.setSpacing(15)

        # Logo/Title
        title = QLabel("DocSeal")
        title_font = QFont()
        title_font.setPointSize(28)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(title)

        # Subtitle
        subtitle = QLabel("Secure Document Management System")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #7f8c8d; font-size: 11pt;")
        container_layout.addWidget(subtitle)

        # Separator
        separator = QLabel("─" * 40)
        separator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(separator)

        # Username
        username_label = QLabel("Username:")
        username_label.setStyleSheet("font-weight: bold;")
        container_layout.addWidget(username_label)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        self.username_input.setText("")
        self.username_input.setMinimumHeight(40)
        container_layout.addWidget(self.username_input)

        # Password
        password_label = QLabel("Password:")
        password_label.setStyleSheet("font-weight: bold;")
        container_layout.addWidget(password_label)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMinimumHeight(40)
        self.password_input.returnPressed.connect(self._login)
        container_layout.addWidget(self.password_input)

        # Info message
        # Login button
        login_btn = QPushButton("Login")
        login_btn.setMinimumHeight(50)
        login_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 4px;
                font-weight: bold;
                font-size: 12pt;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1f618d;
            }
        """)
        login_btn.clicked.connect(self._login)
        container_layout.addWidget(login_btn)

        # Add container to main layout
        layout.addWidget(container)

        # Footer
        from docseal import __version__
        footer = QLabel(f"DocSeal v{__version__} | Secure Document Management")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setStyleSheet("color: #7f8c8d; font-size: 8pt;")
        layout.addWidget(footer)

        self.setLayout(layout)
        self.setStyleSheet("""
            LoginScreen {
                background-color: #f5f6fa;
            }
            QLineEdit {
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                padding: 8px;
                font-size: 10pt;
            }
            QLineEdit:focus {
                border: 2px solid #3498db;
            }
        """)

    def _login(self) -> None:
        """Handle login attempt."""
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Please enter username and password")
            return

        success, message = self.auth_manager.login(username, password)

        if success:
            QMessageBox.information(self, "Success", message)
            self.on_success()
        else:
            QMessageBox.critical(self, "Login Failed", message)
            self.password_input.clear()
