"""CA management tabs for DocSeal GUI."""

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .ca_manager import CAInfo, CertificateAuthority


class InitializeCATab(QWidget):
    """Tab for initializing a new Certificate Authority."""

    def __init__(self, ca_manager: CertificateAuthority) -> None:
        """Initialize the CA tab."""
        super().__init__()
        self.ca_manager = ca_manager
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the UI."""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("🏛️ Initialize Certificate Authority")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Check if CA exists
        if self.ca_manager.ca_exists():
            status_label = QLabel("✓ CA Already Initialized")
            status_label.setStyleSheet(
                "color: #27ae60; font-size: 12pt; font-weight: bold;"
            )
            layout.addWidget(status_label)

            # Show CA info
            ca_info = self.ca_manager.get_ca_info()
            if ca_info:
                info_display = QTextEdit()
                info_display.setText(ca_info)
                info_display.setReadOnly(True)
                layout.addWidget(info_display)

            layout.addStretch()
        else:
            # Form for new CA
            form_group = QGroupBox("CA Configuration")
            form_layout = QVBoxLayout()

            # CA Name
            form_layout.addWidget(QLabel("CA Name:"))
            self.ca_name = QLineEdit()
            self.ca_name.setPlaceholderText("e.g., My University CA")
            form_layout.addWidget(self.ca_name)

            # Organization
            form_layout.addWidget(QLabel("Organization:"))
            self.organization = QLineEdit()
            self.organization.setPlaceholderText("e.g., University of Example")
            form_layout.addWidget(self.organization)

            # Country
            form_layout.addWidget(QLabel("Country:"))
            self.country = QLineEdit()
            self.country.setPlaceholderText("e.g., US")
            self.country.setText("US")
            form_layout.addWidget(self.country)

            # State
            form_layout.addWidget(QLabel("State/Province:"))
            self.state = QLineEdit()
            self.state.setPlaceholderText("e.g., California")
            form_layout.addWidget(self.state)

            # City
            form_layout.addWidget(QLabel("City:"))
            self.city = QLineEdit()
            self.city.setPlaceholderText("e.g., San Francisco")
            form_layout.addWidget(self.city)

            # Email
            form_layout.addWidget(QLabel("Email:"))
            self.email = QLineEdit()
            self.email.setPlaceholderText("admin@example.com")
            form_layout.addWidget(self.email)

            # Valid Days
            form_layout.addWidget(QLabel("Valid for (days):"))
            self.valid_days = QSpinBox()
            self.valid_days.setValue(3650)
            self.valid_days.setMinimum(1)
            self.valid_days.setMaximum(36500)
            form_layout.addWidget(self.valid_days)

            form_group.setLayout(form_layout)
            layout.addWidget(form_group)

            # Initialize button
            init_btn = QPushButton("✅ Initialize CA")
            init_btn.setMinimumHeight(40)
            init_btn.clicked.connect(self._initialize_ca)
            layout.addWidget(init_btn)

            # Status
            self.status = QLabel("")
            self.status.setStyleSheet("color: #7f8c8d; padding: 10px;")
            layout.addWidget(self.status)

            layout.addStretch()

        self.setLayout(layout)

    def _initialize_ca(self) -> None:
        """Initialize the CA."""
        # Basic field check
        if not all(
            [
                self.ca_name.text(),
                self.organization.text(),
                self.country.text(),
                self.state.text(),
                self.city.text(),
                self.email.text(),
            ]
        ):
            QMessageBox.warning(self, "Missing Input", "Please fill all fields")
            return

        # Validate country code (must be exactly 2 characters)
        country = self.country.text().strip()
        if len(country) != 2:
            QMessageBox.warning(
                self,
                "Invalid Country",
                "Country code must be exactly 2 characters (e.g., 'US', 'NP')",
            )
            return

        ca_info = CAInfo(
            name=self.ca_name.text().strip(),
            organization=self.organization.text().strip(),
            country=country.upper(),
            state=self.state.text().strip(),
            city=self.city.text().strip(),
            email=self.email.text().strip(),
            valid_days=self.valid_days.value(),
        )

        success, message = self.ca_manager.initialize_ca(ca_info)

        if success:
            QMessageBox.information(self, "Success", message)
            self.status.setText(message)
            self.status.setStyleSheet("color: #27ae60; padding: 10px;")
        else:
            QMessageBox.critical(self, "Error", message)
            self.status.setText(message)
            self.status.setStyleSheet("color: #e74c3c; padding: 10px;")


class IssueCATab(QWidget):
    """Tab for issuing certificates from the CA."""

    def __init__(self, ca_manager: CertificateAuthority) -> None:
        """Initialize the issue certificate tab."""
        super().__init__()
        self.ca_manager = ca_manager
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the UI."""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("📜 Issue Certificate")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        if not self.ca_manager.ca_exists():
            warning_label = QLabel("⚠️ No CA Initialized")
            warning_label.setStyleSheet("color: #f39c12; font-size: 12pt;")
            layout.addWidget(warning_label)

            info_label = QLabel("Please initialize a CA first using '🏛️ Init CA' tab")
            info_label.setStyleSheet("color: #7f8c8d;")
            layout.addWidget(info_label)

            layout.addStretch()
        else:
            # Form for certificate
            form_group = QGroupBox("Certificate Details")
            form_layout = QVBoxLayout()

            # Common Name
            form_layout.addWidget(QLabel("Common Name:"))
            self.common_name = QLineEdit()
            self.common_name.setPlaceholderText("e.g., John Doe")
            form_layout.addWidget(self.common_name)

            # Organization
            form_layout.addWidget(QLabel("Organization:"))
            self.org = QLineEdit()
            self.org.setPlaceholderText("e.g., University of Example")
            form_layout.addWidget(self.org)

            # Email
            form_layout.addWidget(QLabel("Email:"))
            self.cert_email = QLineEdit()
            self.cert_email.setPlaceholderText("user@example.com")
            form_layout.addWidget(self.cert_email)

            # Valid Days
            form_layout.addWidget(QLabel("Valid for (days):"))
            self.cert_valid_days = QSpinBox()
            self.cert_valid_days.setValue(365)
            self.cert_valid_days.setMinimum(1)
            self.cert_valid_days.setMaximum(3650)
            form_layout.addWidget(self.cert_valid_days)

            form_group.setLayout(form_layout)
            layout.addWidget(form_group)

            # Issue button
            issue_btn = QPushButton("✅ Issue Certificate")
            issue_btn.setMinimumHeight(40)
            issue_btn.clicked.connect(self._issue_certificate)
            layout.addWidget(issue_btn)

            # Status
            self.status = QLabel("")
            self.status.setStyleSheet("color: #7f8c8d; padding: 10px;")
            layout.addWidget(self.status)

            layout.addStretch()

        self.setLayout(layout)

    def _issue_certificate(self) -> None:
        """Issue a certificate."""
        if not all([self.common_name.text(), self.org.text(), self.cert_email.text()]):
            QMessageBox.warning(self, "Missing Input", "Please fill all fields")
            return

        success, message, cert_path = self.ca_manager.issue_certificate(
            common_name=self.common_name.text(),
            organization=self.org.text(),
            email=self.cert_email.text(),
            valid_days=self.cert_valid_days.value(),
        )

        if success:
            full_message = f"{message}\n\nCertificate saved to:\n{cert_path}"
            QMessageBox.information(self, "Success", full_message)
            self.status.setText(message)
            self.status.setStyleSheet("color: #27ae60; padding: 10px;")
            # Clear form
            self.common_name.clear()
            self.org.clear()
            self.cert_email.clear()
        else:
            QMessageBox.critical(self, "Error", message)
            self.status.setText(message)
            self.status.setStyleSheet("color: #e74c3c; padding: 10px;")


class RevokeCATab(QWidget):
    """Tab for revoking certificates."""

    def __init__(self, ca_manager: CertificateAuthority) -> None:
        """Initialize the revoke certificate tab."""
        super().__init__()
        self.ca_manager = ca_manager
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the UI."""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("❌ Revoke Certificate")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        if not self.ca_manager.ca_exists():
            warning_label = QLabel("⚠️ No CA Initialized")
            warning_label.setStyleSheet(
                "color: #f39c12; font-size: 12pt; font-weight: bold;"
            )
            layout.addWidget(warning_label)

            info_label = QLabel(
                "Please initialize a CA first using '🏛️ Initialize CA' tab"
            )
            info_label.setStyleSheet("color: #7f8c8d;")
            layout.addWidget(info_label)

            layout.addStretch()
        else:
            # Get list of certificates
            certs = self.ca_manager.list_certificates()

            if not certs:
                info_label = QLabel("ℹ️ No certificates to revoke")
                info_label.setStyleSheet(
                    "color: #3498db; font-size: 11pt; padding: 15px; "
                    "background-color: #ecf0f1; border-radius: 5px;"
                )
                layout.addWidget(info_label)

                help_label = QLabel(
                    "Issue a certificate first in the '📜 Issue Certificate' tab"
                )
                help_label.setStyleSheet("color: #7f8c8d;")
                layout.addWidget(help_label)

                layout.addStretch()
            else:
                # Certificate selector group
                selector_group = QGroupBox("Available Certificates")
                selector_layout = QVBoxLayout()

                # Combo box with better styling
                selector_layout.addWidget(QLabel("Select certificate to revoke:"))
                self.cert_combo = QComboBox()
                self.cert_combo.addItems(certs)
                self.cert_combo.setMinimumHeight(35)
                self.cert_combo.currentIndexChanged.connect(self._on_cert_selected)
                selector_layout.addWidget(self.cert_combo)

                selector_group.setLayout(selector_layout)
                layout.addWidget(selector_group)

                # Certificate details group
                details_group = QGroupBox("Certificate Details")
                details_layout = QVBoxLayout()

                self.details_text = QTextEdit()
                self.details_text.setReadOnly(True)
                self.details_text.setMaximumHeight(150)
                self.details_text.setStyleSheet(
                    """
                    QTextEdit {
                        background-color: #f8f9fa;
                        border: 1px solid #ddd;
                        border-radius: 4px;
                        padding: 10px;
                    }
                """
                )
                details_layout.addWidget(self.details_text)

                details_group.setLayout(details_layout)
                layout.addWidget(details_group)

                # Load initial details
                self._on_cert_selected()

                # Warning box
                warning_box = QGroupBox("⚠️ Warning")
                warning_layout = QVBoxLayout()
                warning_label = QLabel(
                    "Revoking a certificate cannot be undone. The certificate "
                    "will no longer be valid for signing or verification."
                )
                warning_label.setWordWrap(True)
                warning_label.setStyleSheet("color: #e74c3c; font-size: 10pt;")
                warning_layout.addWidget(warning_label)
                warning_box.setLayout(warning_layout)
                warning_box.setStyleSheet("QGroupBox { border: 1px solid #e74c3c; }")
                layout.addWidget(warning_box)

                # Revoke button
                revoke_btn = QPushButton("❌ Revoke Selected Certificate")
                revoke_btn.setMinimumHeight(45)
                revoke_btn.setStyleSheet(
                    """
                    QPushButton {
                        background-color: #e74c3c;
                        color: white;
                        border: none;
                        font-weight: bold;
                        font-size: 12pt;
                        border-radius: 4px;
                    }
                    QPushButton:hover {
                        background-color: #c0392b;
                    }
                    QPushButton:pressed {
                        background-color: #a93226;
                    }
                """
                )
                revoke_btn.clicked.connect(self._revoke_certificate)
                layout.addWidget(revoke_btn)

                # Status
                self.status = QLabel("")
                self.status.setStyleSheet(
                    "color: #7f8c8d; padding: 10px; border-radius: 4px;"
                )
                layout.addWidget(self.status)

                layout.addStretch()

        self.setLayout(layout)

    def _on_cert_selected(self) -> None:
        """Handle certificate selection change."""
        cert_name = self.cert_combo.currentText()
        if cert_name:
            info = self.ca_manager.get_certificate_info(cert_name)
            self.details_text.setText(info)

    def _revoke_certificate(self) -> None:
        """Revoke the selected certificate."""
        cert_name = self.cert_combo.currentText()

        if not cert_name:
            QMessageBox.warning(
                self, "No Selection", "Please select a certificate to revoke"
            )
            return

        # Confirm revocation with strong warning
        reply = QMessageBox.warning(
            self,
            "Confirm Revocation",
            f"Are you sure you want to REVOKE certificate for:\n\n"
            f"'{cert_name}'?\n\nThis action CANNOT be undone!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        # Find cert file
        cert_path = self.ca_manager.ca_dir / f"{cert_name}_cert.pem"

        if cert_path.exists():
            success, message = self.ca_manager.revoke_certificate(cert_path)

            if success:
                QMessageBox.information(self, "✓ Success", message)
                self.status.setText("✓ Certificate revoked successfully")
                self.status.setStyleSheet(
                    "color: #27ae60; padding: 10px; background-color: #d5f4e6; "
                    "border-radius: 4px;"
                )

                # Refresh combo box
                self.cert_combo.currentIndexChanged.disconnect()
                self.cert_combo.clear()
                certs = self.ca_manager.list_certificates()
                if certs:
                    self.cert_combo.addItems(certs)
                    self.cert_combo.currentIndexChanged.connect(self._on_cert_selected)
                    self._on_cert_selected()
                else:
                    self.cert_combo.addItem("No certificates available")
            else:
                QMessageBox.critical(self, "Error", message)
                self.status.setText(f"✗ Error: {message}")
                self.status.setStyleSheet(
                    "color: #e74c3c; padding: 10px; background-color: #fadbd8; "
                    "border-radius: 4px;"
                )
        else:
            QMessageBox.critical(
                self, "Error", f"Certificate file not found: {cert_path}"
            )
