"""Main application window for DocSeal GUI."""

from typing import Optional
import sys
from pathlib import Path
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QStackedWidget, QStyle, QComboBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon, QFont

from .auth import AuthenticationManager
from .ca_manager import CertificateAuthority
from .login_screen import LoginScreen
from .dashboard import DashboardTab
from .tabs import SignTab, VerifyTab, EncryptTab, DecryptTab, SignEncryptTab, DecryptVerifyTab
from .ca_tabs import InitializeCATab, IssueCATab, RevokeCATab
from .themes import get_stylesheet, get_theme


class MainWindow(QMainWindow):
    """Main application window for DocSeal."""

    def __init__(self) -> None:
        """Initialize the main window."""
        super().__init__()
        self.setWindowTitle("DocSeal - Secure Document Management System")
        self.setWindowIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogYesButton))
        self.setGeometry(100, 100, 1200, 800)

        # Initialize authentication
        self.auth_manager = AuthenticationManager()
        self.ca_manager = CertificateAuthority(Path("data/ca"))
        
        # Store current theme
        self.current_theme = "light"
        self._theme = get_theme(self.current_theme)
        self.sidebar_buttons: list[QPushButton] = []

        # Set stylesheet
        self._apply_theme("light")

        # Show login screen first
        self.login_screen = LoginScreen(self.auth_manager, self._on_login_success)
        self.setCentralWidget(self.login_screen)

    def _apply_theme(self, theme_name: str) -> None:
        """Apply a theme to the application."""
        self.current_theme = theme_name
        self._theme = get_theme(theme_name)
        self.setStyleSheet(get_stylesheet(theme_name))
        self._refresh_sidebar_styles()
        self._restyle_sidebar_shell()
        if hasattr(self, "theme_combo"):
            self.theme_combo.setStyleSheet(
                f"""
                QComboBox {{
                    background-color: {self._theme.sidebar_bg};
                    color: {self._theme.sidebar_text};
                    border: 1px solid {self._theme.border_color};
                    padding: 6px 8px;
                    selection-background-color: {self._theme.button_bg};
                    selection-color: {self._theme.button_text};
                }}
                QComboBox:hover {{
                    border: 1px solid {self._theme.button_bg};
                }}
                QComboBox QAbstractItemView {{
                    background-color: {self._theme.secondary_bg};
                    color: {self._theme.primary_text};
                    selection-background-color: {self._theme.button_bg};
                    selection-color: {self._theme.button_text};
                }}
                QComboBox QAbstractItemView::item {{
                    background-color: {self._theme.secondary_bg};
                    color: {self._theme.primary_text};
                }}
                QComboBox QAbstractItemView::item:selected {{
                    background-color: {self._theme.button_bg};
                    color: {self._theme.button_text};
                }}
                QComboBox QAbstractItemView::item:hover {{
                    background-color: {self._theme.button_hover};
                    color: {self._theme.button_text};
                }}
                """
            )

    def _on_login_success(self) -> None:
        """Handle successful login."""
        # Create main interface
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Create sidebar with tabs
        sidebar = self._create_sidebar()
        main_layout.addWidget(sidebar, 0)

        # Create stacked widget for content
        self.stacked_widget = QStackedWidget()
        main_layout.addWidget(self.stacked_widget, 1)

        # Add all tabs
        self.dashboard_tab = DashboardTab(self.auth_manager, self.ca_manager)
        self.sign_tab = SignTab(self.ca_manager)
        self.verify_tab = VerifyTab()
        self.encrypt_tab = EncryptTab()
        self.decrypt_tab = DecryptTab(self.ca_manager)
        self.sign_encrypt_tab = SignEncryptTab(self.ca_manager)
        self.decrypt_verify_tab = DecryptVerifyTab(self.ca_manager)
        self.init_ca_tab = InitializeCATab(self.ca_manager)
        self.issue_ca_tab = IssueCATab(self.ca_manager)
        self.revoke_ca_tab = RevokeCATab(self.ca_manager)

        self.stacked_widget.addWidget(self.dashboard_tab)        # 0
        self.stacked_widget.addWidget(self.sign_tab)             # 1
        self.stacked_widget.addWidget(self.verify_tab)           # 2
        self.stacked_widget.addWidget(self.encrypt_tab)          # 3
        self.stacked_widget.addWidget(self.decrypt_tab)          # 4
        self.stacked_widget.addWidget(self.sign_encrypt_tab)     # 5
        self.stacked_widget.addWidget(self.decrypt_verify_tab)   # 6
        self.stacked_widget.addWidget(self.init_ca_tab)          # 7
        self.stacked_widget.addWidget(self.issue_ca_tab)         # 8
        self.stacked_widget.addWidget(self.revoke_ca_tab)        # 9

        # Show dashboard by default
        self.stacked_widget.setCurrentIndex(0)
        self._highlight_active_button(0)

    def _create_sidebar(self) -> QWidget:
        """Create the sidebar with navigation buttons."""
        sidebar = QWidget()
        self.sidebar_widget = sidebar
        sidebar.setMaximumWidth(200)
        sidebar.setMinimumWidth(150)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        sidebar.setStyleSheet(f"background-color: {self._theme.sidebar_bg};")

        # Add title with user info
        title = QLabel("DocSeal")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(
            f"padding: 20px; background-color: {self._theme.sidebar_bg}; color: {self._theme.sidebar_text};"
        )
        self.sidebar_title = title
        layout.addWidget(title)

        # User info
        user = self.auth_manager.get_current_user()
        if user:
            user_label = QLabel(f"{user.username}\n({user.role})")
            user_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            user_label.setStyleSheet(
                f"padding: 10px; color: {self._theme.sidebar_text}; font-size: 9pt;"
            )
            layout.addWidget(user_label)

        # Theme selector
        theme_label = QLabel("Theme:")
        theme_label.setStyleSheet("padding: 10px 10px 5px 10px; font-weight: bold;")
        layout.addWidget(theme_label)
        
        theme_combo = QComboBox()
        theme_combo.addItems(["Light", "Dark"])
        theme_combo.currentIndexChanged.connect(self._on_theme_changed)
        # Ensure combo is readable against sidebar background
        theme_combo.setStyleSheet(
            f"""
            QComboBox {{
                background-color: {self._theme.sidebar_bg};
                color: {self._theme.sidebar_text};
                border: 1px solid {self._theme.border_color};
                padding: 6px 8px;
                selection-background-color: {self._theme.button_bg};
                selection-color: {self._theme.button_text};
            }}
            QComboBox:hover {{
                border: 1px solid {self._theme.button_bg};
            }}
            QComboBox QAbstractItemView {{
                background-color: {self._theme.secondary_bg};
                color: {self._theme.primary_text};
                selection-background-color: {self._theme.button_bg};
                selection-color: {self._theme.button_text};
            }}
            QComboBox QAbstractItemView::item {{
                background-color: {self._theme.secondary_bg};
                color: {self._theme.primary_text};
            }}
            QComboBox QAbstractItemView::item:selected {{
                background-color: {self._theme.button_bg};
                color: {self._theme.button_text};
            }}
            QComboBox QAbstractItemView::item:hover {{
                background-color: {self._theme.button_hover};
                color: {self._theme.button_text};
            }}
            """
        )
        layout.addWidget(theme_combo)
        self.theme_combo = theme_combo

        # Navigation buttons
        buttons = [
            ("Dashboard", 0, "Overview and status"),
            ("Sign", 1, "Create digital signatures"),
            ("Verify", 2, "Verify document signatures"),
            ("Encrypt", 3, "Encrypt documents"),
            ("Decrypt", 4, "Decrypt documents"),
            ("Sign + Encrypt", 5, "Sign and encrypt documents"),
            ("Decrypt + Verify", 6, "Decrypt and verify documents"),
            ("Init CA", 7, "Initialize CA"),
            ("Issue Cert", 8, "Issue certificates"),
            ("Revoke Cert", 9, "Revoke certificates"),
        ]

        for text, index, tooltip in buttons:
            btn = QPushButton(text)
            btn.setMinimumHeight(50)
            btn.setToolTip(tooltip)
            btn.clicked.connect(lambda checked, idx=index: self._switch_tab(idx))
            self.sidebar_buttons.append(btn)
            layout.addWidget(btn)
        self._refresh_sidebar_styles()

        # Add stretch
        layout.addStretch()

        # Logout button
        logout_btn = QPushButton("Logout")
        logout_btn.setMinimumHeight(40)
        logout_btn.clicked.connect(self._logout)
        logout_btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {self._theme.error_bg};
                color: {self._theme.error_text};
                border: none;
                font-weight: bold;
                padding: 10px;
            }}
            QPushButton:hover {{
                background-color: {self._theme.button_hover};
            }}
        """
        )
        self.logout_btn = logout_btn
        layout.addWidget(logout_btn)

        # Add footer with version
        from docseal import __version__
        footer = QLabel(f"v{__version__}")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setStyleSheet(
            f"padding: 10px; color: {self._theme.secondary_text}; font-size: 9pt;"
        )
        self.footer_label = footer
        layout.addWidget(footer)

        return sidebar

    def _switch_tab(self, index: int) -> None:
        """Switch to the specified tab."""
        self.stacked_widget.setCurrentIndex(index)
        self._highlight_active_button(index)

    def _on_theme_changed(self, index: int) -> None:
        """Handle theme change."""
        theme_name = "light" if index == 0 else "dark"
        self._apply_theme(theme_name)
        self._highlight_active_button(self.stacked_widget.currentIndex())

    def _logout(self) -> None:
        """Log out the current user."""
        self.auth_manager.logout()
        self.login_screen = LoginScreen(self.auth_manager, self._on_login_success)
        self.setCentralWidget(self.login_screen)

    def _refresh_sidebar_styles(self) -> None:
        """Apply theme-consistent styles to sidebar buttons."""
        if not hasattr(self, "sidebar_buttons"):
            return
        for btn in self.sidebar_buttons:
            btn.setStyleSheet(
                f"""
                QPushButton {{
                    background-color: {self._theme.secondary_bg};
                    border: none;
                    text-align: left;
                    padding: 10px 15px;
                    font-size: 10pt;
                    color: {self._theme.primary_text};
                }}
                QPushButton:hover {{
                    background-color: {self._theme.button_hover};
                    color: {self._theme.button_text};
                }}
                QPushButton:pressed {{
                    background-color: {self._theme.button_pressed};
                    color: {self._theme.button_text};
                }}
            """
            )

    def _restyle_sidebar_shell(self) -> None:
        """Refresh sidebar container/title/footer colors when theme changes."""
        if hasattr(self, "sidebar_widget"):
            self.sidebar_widget.setStyleSheet(
                f"background-color: {self._theme.sidebar_bg};"
            )
        if hasattr(self, "sidebar_title"):
            self.sidebar_title.setStyleSheet(
                f"padding: 20px; background-color: {self._theme.sidebar_bg}; color: {self._theme.sidebar_text};"
            )
        if hasattr(self, "logout_btn"):
            self.logout_btn.setStyleSheet(
                f"""
                QPushButton {{
                    background-color: {self._theme.error_bg};
                    color: {self._theme.error_text};
                    border: none;
                    font-weight: bold;
                    padding: 10px;
                }}
                QPushButton:hover {{
                    background-color: {self._theme.button_hover};
                }}
            """
            )
        if hasattr(self, "footer_label"):
            self.footer_label.setStyleSheet(
                f"padding: 10px; color: {self._theme.secondary_text}; font-size: 9pt;"
            )

    def _highlight_active_button(self, active_index: int) -> None:
        """Visually mark the active navigation button."""
        for i, btn in enumerate(self.sidebar_buttons):
            if i == active_index:
                btn.setStyleSheet(
                    f"""
                    QPushButton {{
                        background-color: {self._theme.button_bg};
                        color: {self._theme.button_text};
                        border: none;
                        text-align: left;
                        padding: 10px 15px;
                        font-size: 10pt;
                        font-weight: bold;
                    }}
                    QPushButton:hover {{
                        background-color: {self._theme.button_hover};
                        color: {self._theme.button_text};
                    }}
                """
                )
            else:
                btn.setStyleSheet(
                    f"""
                    QPushButton {{
                        background-color: {self._theme.secondary_bg};
                        border: none;
                        text-align: left;
                        padding: 10px 15px;
                        font-size: 10pt;
                        color: {self._theme.primary_text};
                    }}
                    QPushButton:hover {{
                        background-color: {self._theme.button_hover};
                        color: {self._theme.button_text};
                    }}
                """
                )
