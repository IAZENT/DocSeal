"""Dashboard tab for DocSeal GUI."""

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QGroupBox,
    QLabel,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .auth import AuthenticationManager
from .ca_manager import CertificateAuthority


class DashboardTab(QWidget):
    """Dashboard tab showing system status and information."""

    def __init__(
        self, auth_manager: AuthenticationManager, ca_manager: CertificateAuthority
    ) -> None:
        """
        Initialize the dashboard tab.

        Args:
            auth_manager: Authentication manager
            ca_manager: Certificate Authority manager
        """
        super().__init__()
        self.auth_manager = auth_manager
        self.ca_manager = ca_manager
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the UI."""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Dashboard")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # User Information
        user_group = QGroupBox("User Information")
        user_layout = QVBoxLayout()

        user = self.auth_manager.get_current_user()
        if user:
            user_info = f"""
            Username: {user.username}
            Role: {user.role.upper()}
            Email: {user.email}
            Organization: {user.organization}
            Logged in at: {user.logged_in_at.strftime('%Y-%m-%d %H:%M:%S')}
            """
            user_label = QLabel(user_info.strip())
            user_label.setStyleSheet("line-height: 1.8;")
            user_layout.addWidget(user_label)

        user_group.setLayout(user_layout)
        layout.addWidget(user_group)

        # CA Status
        ca_group = QGroupBox("Certificate Authority Status")
        ca_layout = QVBoxLayout()

        if self.ca_manager.ca_exists():
            ca_status = QLabel("CA Initialized")
            ca_status.setStyleSheet("font-weight: bold;")
            ca_layout.addWidget(ca_status)

            # CA Info
            ca_info = self.ca_manager.get_ca_info()
            if ca_info:
                ca_info_text = QTextEdit()
                ca_info_text.setText(ca_info)
                ca_info_text.setReadOnly(True)
                ca_info_text.setMaximumHeight(150)
                ca_layout.addWidget(ca_info_text)

            # Issued certificates
            certs = self.ca_manager.list_certificates()
            if certs:
                cert_label = QLabel(f"Issued Certificates: {len(certs)}")
                cert_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
                ca_layout.addWidget(cert_label)

                cert_list = QTextEdit()
                cert_list.setText("\n".join(f"• {cert}" for cert in certs))
                cert_list.setReadOnly(True)
                cert_list.setMaximumHeight(100)
                ca_layout.addWidget(cert_list)
        else:
            ca_status = QLabel("CA Not Initialized")
            ca_status.setStyleSheet("font-weight: bold;")
            ca_layout.addWidget(ca_status)

            info_label = QLabel(
                "Click 'Init CA' in the menu to initialize a new Certificate Authority"
            )
            ca_layout.addWidget(info_label)

        ca_group.setLayout(ca_layout)
        layout.addWidget(ca_group)

        # System Information
        system_group = QGroupBox("System Information")
        system_layout = QVBoxLayout()

        from docseal import __version__

        system_info = f"""
        Version: {__version__}
        Framework: PyQt6
        Cryptography: RSA-PSS, AES-256-GCM
        Format: .dseal (ZIP-based)
        Status: Production Ready
        """

        system_label = QLabel(system_info.strip())
        system_label.setStyleSheet("line-height: 1.8;")
        system_layout.addWidget(system_label)

        system_group.setLayout(system_layout)
        layout.addWidget(system_group)

        # Add stretch
        layout.addStretch()

        self.setLayout(layout)
