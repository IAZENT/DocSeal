"""GUI tabs for DocSeal operations."""

from typing import Optional
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QFileDialog, QTextEdit, QGroupBox, QMessageBox, QProgressBar, QCheckBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

from .service_wrapper import GUIDocSealService
from .ca_manager import CertificateAuthority
from ..core.envelope import DsealEnvelope


class WorkerThread(QThread):
    """Worker thread for long-running operations."""

    finished = pyqtSignal()
    error = pyqtSignal(str)
    success = pyqtSignal(str)

    def __init__(self, operation, *args, parent=None, **kwargs):
        super().__init__(parent)
        self.operation = operation
        self.args = args
        self.kwargs = kwargs
        self.setObjectName("WorkerThread")  # For debugging

    def run(self):
        """Run the operation."""
        try:
            result = self.operation(*self.args, **self.kwargs)
            if result:
                self.success.emit(str(result))
            self.finished.emit()
        except Exception as e:
            self.error.emit(f"Error: {str(e)}")
            self.finished.emit()
        # No explicit quit/wait here; letting the thread exit naturally avoids
        # deadlock and "QThread: Destroyed while thread is still running" errors.


class SignTab(QWidget):
    """Tab for signing documents."""

    def __init__(self, ca_manager: Optional[CertificateAuthority] = None):
        super().__init__()
        self.service = GUIDocSealService()
        self.ca_manager = ca_manager
        self.init_ui()

    def init_ui(self):
        """Initialize the UI."""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("📄 Sign Document")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # CA checkbox (shown always; disabled if CA missing)
        ca_group = QGroupBox("Certificate Authority")
        ca_layout = QVBoxLayout()
        self.use_ca_checkbox = QCheckBox("Use CA Certificate and Key")
        if not (self.ca_manager and self.ca_manager.ca_exists()):
            self.use_ca_checkbox.setEnabled(False)
            self.use_ca_checkbox.setToolTip("Initialize CA first in the CA tab")
        self.use_ca_checkbox.stateChanged.connect(self._toggle_ca_usage)
        ca_layout.addWidget(self.use_ca_checkbox)
        ca_group.setLayout(ca_layout)
        layout.addWidget(ca_group)

        # Document selection
        doc_group = self._create_file_selector("Document to Sign:", "document_path")
        layout.addWidget(doc_group)

        # Private key selection
        key_group = self._create_file_selector("Private Key:", "key_path")
        layout.addWidget(key_group)

        # Certificate selection
        cert_group = self._create_file_selector("Certificate:", "cert_path")
        layout.addWidget(cert_group)

        # Output file
        output_group = self._create_file_selector("Save As:", "output_path", save=True)
        layout.addWidget(output_group)

        # Description
        desc_label = QLabel("Description (optional):")
        layout.addWidget(desc_label)
        self.description = QTextEdit()
        self.description.setMaximumHeight(80)
        self.description.setPlaceholderText("Enter a description for this signature...")
        layout.addWidget(self.description)

        # Sign button
        sign_btn = QPushButton("Sign Document")
        sign_btn.setMinimumHeight(40)
        sign_btn.setStyleSheet("font-size: 11pt; font-weight: bold;")
        sign_btn.clicked.connect(self._sign)
        layout.addWidget(sign_btn)

        # Status
        self.status = QLabel("Ready to sign documents")
        self.status.setStyleSheet("color: #7f8c8d; padding: 10px;")
        layout.addWidget(self.status)

        layout.addStretch()
        self.setLayout(layout)

    def _create_file_selector(self, label: str, attr: str, save: bool = False) -> QGroupBox:
        """Create a file selector group."""
        group = QGroupBox(label)
        layout = QHBoxLayout()

        # Text field
        field = QLineEdit()
        field.setReadOnly(True)
        setattr(self, attr, field)
        layout.addWidget(field)

        # Browse button
        browse_btn = QPushButton("Browse...")
        if save:
            browse_btn.clicked.connect(lambda: self._browse_save(field))
        else:
            browse_btn.clicked.connect(lambda: self._browse_open(field))
        layout.addWidget(browse_btn)

        group.setLayout(layout)
        return group

    def _toggle_ca_usage(self):
        """Toggle CA usage and auto-populate fields."""
        if not self.use_ca_checkbox:
            return
        if self.use_ca_checkbox.isChecked():
            if self.ca_manager and self.ca_manager.ca_exists():
                self.key_path.setText(str(self.ca_manager.ca_key_path))
                self.cert_path.setText(str(self.ca_manager.ca_cert_path))
                self.key_path.setReadOnly(True)
                self.cert_path.setReadOnly(True)
            else:
                QMessageBox.warning(self, "CA not available", "Initialize the CA in the CA tab first.")
                self.use_ca_checkbox.setChecked(False)
        else:
            self.key_path.setReadOnly(False)
            self.cert_path.setReadOnly(False)
            self.key_path.clear()
            self.cert_path.clear()

    def _browse_open(self, field: QLineEdit):
        """Open file browser for opening files."""
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            field.setText(path)
            if field is getattr(self, "envelope_path", None) and not self.output_path.text():
                default = Path(path).with_suffix(".decrypted")
                self.output_path.setText(str(default))
            if field is getattr(self, "document_path", None) and not self.output_path.text():
                default = Path(path).with_suffix(".signed_encrypted.dseal")
                self.output_path.setText(str(default))
            if field is getattr(self, "envelope_path", None) and not self.output_path.text():
                default = Path(path).with_suffix(".decrypted")
                self.output_path.setText(str(default))
            if field is getattr(self, "document_path", None) and not self.output_path.text():
                default = Path(path).with_suffix(".encrypted.dseal")
                self.output_path.setText(str(default))
            if field is getattr(self, "document_path", None) and not self.output_path.text():
                default = Path(path).with_suffix(".dseal")
                self.output_path.setText(str(default))

    def _browse_save(self, field: QLineEdit):
        """Open file browser for saving files."""
        path, _ = QFileDialog.getSaveFileName(self, "Save As", filter="DocSeal Envelopes (*.dseal)")
        if path:
            if not path.endswith('.dseal'):
                path += '.dseal'
            field.setText(path)

    def _sign(self):
        """Sign the document."""
        doc_path = self.document_path.text()
        key_path = self.key_path.text()
        cert_path = self.cert_path.text()
        output_path = self.output_path.text()
        description = self.description.toPlainText()

        if not all([doc_path, key_path, cert_path, output_path]):
            QMessageBox.warning(self, "Missing Input", "Please select all required files.")
            return

        self.status.setText("Signing... please wait")
        self.status.setStyleSheet("color: #f39c12; padding: 10px;")

        def sign_op():
            return self.service.sign(
                Path(doc_path),
                Path(key_path),
                Path(cert_path),
                Path(output_path),
                description
            )

        thread = WorkerThread(sign_op, parent=self)
        thread.success.connect(lambda msg: self._on_success(f"Document signed successfully!\nSaved to: {output_path}"))
        thread.error.connect(self._on_error)
        thread.finished.connect(lambda: self._set_ready("Ready to sign documents"))
        thread.start()

    def _on_success(self, message: str):
        """Handle successful operation."""
        self.status.setText(message)
        self.status.setStyleSheet("color: #27ae60; padding: 10px;")
        QMessageBox.information(self, "Success", message)
        # Reset form
        self.document_path.setText("")
        self.key_path.setText("")
        self.cert_path.setText("")
        self.output_path.setText("")
        self.description.clear()

    def _on_error(self, error: str):
        """Handle error."""
        self.status.setText(error)
        self.status.setStyleSheet("color: #e74c3c; padding: 10px;")
        QMessageBox.critical(self, "Error", error)

    def _set_ready(self, message: str) -> None:
        """Reset status label to a ready state."""
        self.status.setText(message)
        self.status.setStyleSheet("color: #7f8c8d; padding: 10px;")


class VerifyTab(QWidget):
    """Tab for verifying signatures."""

    def __init__(self):
        super().__init__()
        self.service = GUIDocSealService()
        self.init_ui()

    def init_ui(self):
        """Initialize the UI."""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Verify Signature")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Envelope selection
        env_group = self._create_file_selector("Envelope File:", "envelope_path")
        layout.addWidget(env_group)

        # Certificate selection
        cert_group = self._create_file_selector("Signer Certificate:", "cert_path")
        layout.addWidget(cert_group)

        # Verify button
        verify_btn = QPushButton("Verify Signature")
        verify_btn.setMinimumHeight(40)
        verify_btn.setStyleSheet("font-size: 11pt; font-weight: bold;")
        verify_btn.clicked.connect(self._verify)
        layout.addWidget(verify_btn)

        # Results
        self.results = QTextEdit()
        self.results.setReadOnly(True)
        self.results.setMinimumHeight(200)
        layout.addWidget(QLabel("Verification Results:"))
        layout.addWidget(self.results)

        # Status
        self.status = QLabel("Ready to verify signatures")
        self.status.setStyleSheet("color: #7f8c8d; padding: 10px;")
        layout.addWidget(self.status)

        layout.addStretch()
        self.setLayout(layout)

    def _create_file_selector(self, label: str, attr: str) -> QGroupBox:
        """Create a file selector group."""
        group = QGroupBox(label)
        layout = QHBoxLayout()

        field = QLineEdit()
        field.setReadOnly(True)
        setattr(self, attr, field)
        layout.addWidget(field)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(lambda: self._browse(field))
        layout.addWidget(browse_btn)

        group.setLayout(layout)
        return group

    def _browse(self, field: QLineEdit):
        """Open file browser."""
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            field.setText(path)

    def _verify(self):
        """Verify the signature."""
        env_path = self.envelope_path.text()

        if not env_path:
            QMessageBox.warning(self, "Missing Input", "Please select the envelope to verify.")
            return

        self.status.setText("Verifying... please wait")
        self.status.setStyleSheet("color: #f39c12; padding: 10px;")
        self.results.clear()

        def verify_op():
            result = self.service.verify(Path(env_path))
            return result

        thread = WorkerThread(verify_op, parent=self)
        thread.success.connect(self._display_results)
        thread.error.connect(self._on_error)
        thread.finished.connect(lambda: None)
        thread.start()

    def _display_results(self, result_str: str):
        """Display verification results."""
        try:
            from ..core.verification import VerificationResult
            # Parse and display the result
            self.results.setText(result_str)
            self.status.setText("Signature is valid")
            self.status.setStyleSheet("color: #27ae60; padding: 10px;")
        except Exception as e:
            self._on_error(str(e))

    def _on_error(self, error: str):
        """Handle error."""
        self.status.setText(error)
        self.status.setStyleSheet("color: #e74c3c; padding: 10px;")
        self.results.setText(error)


class EncryptTab(QWidget):
    """Tab for encrypting documents."""

    def __init__(self):
        super().__init__()
        self.service = GUIDocSealService()
        self.init_ui()

    def init_ui(self):
        """Initialize the UI."""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Encrypt Document")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Document selection
        doc_group = self._create_file_selector("Document to Encrypt:", "document_path")
        layout.addWidget(doc_group)

        # Recipient certificate
        cert_group = self._create_file_selector("Recipient Certificate:", "cert_path")
        layout.addWidget(cert_group)

        # Output file
        output_group = self._create_file_selector("Save As:", "output_path", save=True)
        layout.addWidget(output_group)

        # Encrypt button
        encrypt_btn = QPushButton("Encrypt Document")
        encrypt_btn.setMinimumHeight(40)
        encrypt_btn.setStyleSheet("font-size: 11pt; font-weight: bold;")
        encrypt_btn.clicked.connect(self._encrypt)
        layout.addWidget(encrypt_btn)

        # Status
        self.status = QLabel("Ready to encrypt documents")
        self.status.setStyleSheet("color: #7f8c8d; padding: 10px;")
        layout.addWidget(self.status)

        layout.addStretch()
        self.setLayout(layout)

    def _create_file_selector(self, label: str, attr: str, save: bool = False) -> QGroupBox:
        """Create a file selector group."""
        group = QGroupBox(label)
        layout = QHBoxLayout()

        field = QLineEdit()
        field.setReadOnly(True)
        setattr(self, attr, field)
        layout.addWidget(field)

        browse_btn = QPushButton("Browse...")
        if save:
            browse_btn.clicked.connect(lambda: self._browse_save(field))
        else:
            browse_btn.clicked.connect(lambda: self._browse_open(field))
        layout.addWidget(browse_btn)

        group.setLayout(layout)
        return group

    def _browse_open(self, field: QLineEdit):
        """Open file browser for opening files."""
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            field.setText(path)

    def _browse_save(self, field: QLineEdit):
        """Open file browser for saving files."""
        path, _ = QFileDialog.getSaveFileName(self, "Save As", filter="DocSeal Envelopes (*.dseal)")
        if path:
            if not path.endswith('.dseal'):
                path += '.dseal'
            field.setText(path)

    def _encrypt(self):
        """Encrypt the document."""
        doc_path = self.document_path.text()
        cert_path = self.cert_path.text()
        output_path = self.output_path.text()

        if not all([doc_path, cert_path, output_path]):
            QMessageBox.warning(self, "Missing Input", "Please select all required files.")
            return

        self.status.setText("Encrypting... please wait")
        self.status.setStyleSheet("color: #f39c12; padding: 10px;")

        def encrypt_op():
            return self.service.encrypt(Path(doc_path), Path(cert_path), Path(output_path))

        thread = WorkerThread(encrypt_op, parent=self)
        thread.success.connect(lambda: self._on_success(f"Document encrypted successfully!\nSaved to: {output_path}"))
        thread.error.connect(self._on_error)
        thread.finished.connect(lambda: None)
        thread.start()

    def _on_success(self, message: str):
        """Handle successful operation."""
        self.status.setText(message)
        self.status.setStyleSheet("color: #27ae60; padding: 10px;")
        QMessageBox.information(self, "Success", message)
        # Reset form
        self.document_path.setText("")
        self.cert_path.setText("")
        self.output_path.setText("")

    def _on_error(self, error: str):
        """Handle error."""
        self.status.setText(error)
        self.status.setStyleSheet("color: #e74c3c; padding: 10px;")
        QMessageBox.critical(self, "Error", error)


class DecryptTab(QWidget):
    """Tab for decrypting documents."""

    def __init__(self, ca_manager: Optional[CertificateAuthority] = None):
        super().__init__()
        self.service = GUIDocSealService()
        self.ca_manager = ca_manager
        self.use_ca_checkbox: Optional[QCheckBox] = None
        self.init_ui()

    def init_ui(self):
        """Initialize the UI."""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Decrypt Document")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Envelope selection
        env_group = self._create_file_selector("Encrypted Envelope:", "envelope_path")
        layout.addWidget(env_group)

        # CA checkbox
        ca_group = QGroupBox("Key Source")
        ca_layout = QVBoxLayout()
        self.use_ca_checkbox = QCheckBox("Use CA Private Key")
        if not (self.ca_manager and self.ca_manager.ca_exists()):
            self.use_ca_checkbox.setEnabled(False)
            self.use_ca_checkbox.setToolTip("Initialize CA first in the CA tab")
        self.use_ca_checkbox.stateChanged.connect(self._toggle_ca_usage)
        ca_layout.addWidget(self.use_ca_checkbox)
        ca_group.setLayout(ca_layout)
        layout.addWidget(ca_group)

        # Private key selection
        key_group = self._create_file_selector("Private Key:", "key_path")
        layout.addWidget(key_group)

        # Output file
        output_group = self._create_file_selector("Save As:", "output_path", save=True)
        layout.addWidget(output_group)

        # Decrypt button
        decrypt_btn = QPushButton("Decrypt Document")
        decrypt_btn.setMinimumHeight(40)
        decrypt_btn.setStyleSheet("font-size: 11pt; font-weight: bold;")
        decrypt_btn.clicked.connect(self._decrypt)
        layout.addWidget(decrypt_btn)

        # Status
        self.status = QLabel("Ready to decrypt documents")
        self.status.setStyleSheet("color: #7f8c8d; padding: 10px;")
        layout.addWidget(self.status)

        layout.addStretch()
        self.setLayout(layout)

    def _create_file_selector(self, label: str, attr: str, save: bool = False) -> QGroupBox:
        """Create a file selector group."""
        group = QGroupBox(label)
        layout = QHBoxLayout()

        field = QLineEdit()
        field.setReadOnly(True)
        setattr(self, attr, field)
        layout.addWidget(field)

        browse_btn = QPushButton("Browse...")
        if save:
            browse_btn.clicked.connect(lambda: self._browse_save(field))
        else:
            browse_btn.clicked.connect(lambda: self._browse_open(field))
        layout.addWidget(browse_btn)

        group.setLayout(layout)
        return group

    def _browse_open(self, field: QLineEdit):
        """Open file browser for opening files."""
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            field.setText(path)

    def _browse_save(self, field: QLineEdit):
        """Open file browser for saving files."""
        path, _ = QFileDialog.getSaveFileName(self, "Save As")
        if path:
            field.setText(path)

    def _decrypt(self):
        """Decrypt the document."""
        env_path = self.envelope_path.text()
        key_path = self.key_path.text()
        output_path = self.output_path.text()

        if not all([env_path, key_path, output_path]):
            QMessageBox.warning(self, "Missing Input", "Please select all required files.")
            return

        self.status.setText("Decrypting... please wait")
        self.status.setStyleSheet("color: #f39c12; padding: 10px;")

        def decrypt_op():
            return self.service.decrypt(Path(env_path), Path(key_path), Path(output_path))

        thread = WorkerThread(decrypt_op, parent=self)
        thread.success.connect(lambda: self._on_success(f"Document decrypted successfully!\nSaved to: {output_path}"))
        thread.error.connect(self._on_error)
        thread.finished.connect(lambda: None)
        thread.start()

    def _toggle_ca_usage(self):
        """Auto-fill private key from CA if available."""
        if not self.use_ca_checkbox:
            return
        if self.use_ca_checkbox.isChecked():
            if self.ca_manager and self.ca_manager.ca_exists():
                self.key_path.setText(str(self.ca_manager.ca_key_path))
                self.key_path.setReadOnly(True)
            else:
                QMessageBox.warning(self, "CA not available", "Initialize the CA in the CA tab first.")
                self.use_ca_checkbox.setChecked(False)
        else:
            self.key_path.setReadOnly(False)
            self.key_path.clear()

    def _on_success(self, message: str):
        """Handle successful operation."""
        self.status.setText(message)
        self.status.setStyleSheet("color: #27ae60; padding: 10px;")
        QMessageBox.information(self, "Success", message)
        # Reset form
        self.envelope_path.setText("")
        self.key_path.setText("")
        self.output_path.setText("")

    def _on_error(self, error: str):
        """Handle error."""
        self.status.setText(error)
        self.status.setStyleSheet("color: #e74c3c; padding: 10px;")
        QMessageBox.critical(self, "Error", error)

class SignEncryptTab(QWidget):
    """Tab for signing and encrypting documents (two-layer envelope)."""

    def __init__(self, ca_manager: Optional[CertificateAuthority] = None):
        super().__init__()
        self.service = GUIDocSealService()
        self.ca_manager = ca_manager
        self.use_ca_checkbox: Optional[QCheckBox] = None
        self.init_ui()

    def init_ui(self):
        """Initialize the UI."""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Sign & Encrypt Document")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Description
        desc = QLabel(
            "Sign a document with your key, then encrypt it for a recipient.\n"
            "This creates a two-layer envelope: signature + encryption."
        )
        desc.setStyleSheet("color: #7f8c8d; padding: 10px;")
        layout.addWidget(desc)

        # CA checkbox (shown always; disabled if CA missing)
        ca_group = QGroupBox("Certificate Authority")
        ca_layout = QVBoxLayout()
        self.use_ca_checkbox = QCheckBox("Use CA Certificate and Key for signing")
        if not (self.ca_manager and self.ca_manager.ca_exists()):
            self.use_ca_checkbox.setEnabled(False)
            self.use_ca_checkbox.setToolTip("Initialize CA first in the CA tab")
        self.use_ca_checkbox.stateChanged.connect(self._toggle_ca_usage)
        ca_layout.addWidget(self.use_ca_checkbox)
        ca_group.setLayout(ca_layout)
        layout.addWidget(ca_group)

        # Document selection
        doc_group = self._create_file_selector("Document to Sign & Encrypt:", "document_path")
        layout.addWidget(doc_group)

        # Signer key selection
        key_group = self._create_file_selector("Your Private Key:", "key_path")
        layout.addWidget(key_group)

        # Signer certificate selection
        signer_cert_group = self._create_file_selector("Your Certificate:", "cert_path")
        layout.addWidget(signer_cert_group)

        # Recipient certificate selection
        recipient_cert_group = self._create_file_selector("Recipient's Certificate:", "recipient_cert_path")
        layout.addWidget(recipient_cert_group)

        # Description field
        desc_group = QGroupBox("Signature Description (Optional):")
        desc_layout = QVBoxLayout()
        self.description = QTextEdit()
        self.description.setMinimumHeight(60)
        self.description.setPlaceholderText("Enter signature description (e.g., 'Approved by Finance Team')")
        desc_layout.addWidget(self.description)
        desc_group.setLayout(desc_layout)
        layout.addWidget(desc_group)

        # Output file
        output_group = self._create_file_selector("Save As:", "output_path", save=True)
        layout.addWidget(output_group)

        # Sign & Encrypt button
        sign_encrypt_btn = QPushButton("Sign & Encrypt Document")
        sign_encrypt_btn.setMinimumHeight(40)
        sign_encrypt_btn.setStyleSheet("font-size: 11pt; font-weight: bold;")
        sign_encrypt_btn.clicked.connect(self._sign_encrypt)
        layout.addWidget(sign_encrypt_btn)

        # Status
        self.status = QLabel("Ready to sign and encrypt documents")
        self.status.setStyleSheet("color: #7f8c8d; padding: 10px;")
        layout.addWidget(self.status)

        layout.addStretch()
        self.setLayout(layout)

    def _create_file_selector(self, label: str, attr: str, save: bool = False) -> QGroupBox:
        """Create a file selector group."""
        group = QGroupBox(label)
        layout = QHBoxLayout()

        field = QLineEdit()
        field.setReadOnly(True)
        setattr(self, attr, field)
        layout.addWidget(field)

        browse_btn = QPushButton("Browse...")
        if save:
            browse_btn.clicked.connect(lambda: self._browse_save(field))
        else:
            browse_btn.clicked.connect(lambda: self._browse_open(field))
        layout.addWidget(browse_btn)

        group.setLayout(layout)
        return group

    def _browse_open(self, field: QLineEdit):
        """Open file browser for opening files."""
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            field.setText(path)

    def _browse_save(self, field: QLineEdit):
        """Open file browser for saving files."""
        path, _ = QFileDialog.getSaveFileName(self, "Save As", filter="DocSeal Envelopes (*.dseal)")
        if path:
            if not path.endswith('.dseal'):
                path += '.dseal'
            field.setText(path)

    def _sign_encrypt(self):
        """Sign and encrypt the document."""
        doc_path = self.document_path.text()
        key_path = self.key_path.text()
        cert_path = self.cert_path.text()
        recipient_cert_path = self.recipient_cert_path.text()
        output_path = self.output_path.text()
        description = self.description.toPlainText()

        if not all([doc_path, key_path, cert_path, recipient_cert_path, output_path]):
            QMessageBox.warning(self, "Missing Input", "Please select all required files.")
            return

        self.status.setText("Signing and encrypting... please wait")
        self.status.setStyleSheet("color: #f39c12; padding: 10px;")

        def sign_encrypt_op():
            return self.service.sign_encrypt(
                Path(doc_path),
                Path(key_path),
                Path(cert_path),
                Path(recipient_cert_path),
                Path(output_path),
                description
            )

        thread = WorkerThread(sign_encrypt_op, parent=self)
        thread.success.connect(
            lambda: self._on_success(f"Document signed and encrypted successfully!\nSaved to: {output_path}")
        )
        thread.error.connect(self._on_error)
        thread.finished.connect(lambda: None)
        thread.start()

    def _toggle_ca_usage(self):
        """Auto-fill signer key/cert from CA if available."""
        if not self.use_ca_checkbox:
            return
        if self.use_ca_checkbox.isChecked():
            if self.ca_manager and self.ca_manager.ca_exists():
                self.key_path.setText(str(self.ca_manager.ca_key_path))
                self.cert_path.setText(str(self.ca_manager.ca_cert_path))
                self.key_path.setReadOnly(True)
                self.cert_path.setReadOnly(True)
            else:
                QMessageBox.warning(self, "CA not available", "Initialize the CA in the CA tab first.")
                self.use_ca_checkbox.setChecked(False)
        else:
            self.key_path.setReadOnly(False)
            self.cert_path.setReadOnly(False)
            self.key_path.clear()
            self.cert_path.clear()

    def _on_success(self, message: str):
        """Handle successful operation."""
        self.status.setText(message)
        self.status.setStyleSheet("color: #27ae60; padding: 10px;")
        QMessageBox.information(self, "Success", message)
        # Reset form
        self.document_path.setText("")
        self.key_path.setText("")
        self.cert_path.setText("")
        self.recipient_cert_path.setText("")
        self.output_path.setText("")
        self.description.clear()

    def _on_error(self, error: str):
        """Handle error."""
        self.status.setText(error)
        self.status.setStyleSheet("color: #e74c3c; padding: 10px;")
        QMessageBox.critical(self, "Error", error)


class DecryptVerifyTab(QWidget):
    """Tab for decrypting and verifying signed-encrypted documents."""

    def __init__(self, ca_manager: Optional[CertificateAuthority] = None):
        super().__init__()
        self.service = GUIDocSealService()
        self.ca_manager = ca_manager
        self.use_ca_checkbox: Optional[QCheckBox] = None
        self.init_ui()

    def init_ui(self):
        """Initialize the UI."""
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Decrypt & Verify Document")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Description
        desc = QLabel(
            "Decrypt an encrypted document and verify its digital signature.\n"
            "Validates both the signer's identity and document integrity."
        )
        desc.setStyleSheet("color: #7f8c8d; padding: 10px;")
        layout.addWidget(desc)

        # Envelope selection
        env_group = self._create_file_selector("Encrypted Envelope:", "envelope_path")
        layout.addWidget(env_group)

        # CA checkbox
        ca_group = QGroupBox("Key Source")
        ca_layout = QVBoxLayout()
        self.use_ca_checkbox = QCheckBox("Use CA Private Key")
        if not (self.ca_manager and self.ca_manager.ca_exists()):
            self.use_ca_checkbox.setEnabled(False)
            self.use_ca_checkbox.setToolTip("Initialize CA first in the CA tab")
        self.use_ca_checkbox.stateChanged.connect(self._toggle_ca_usage)
        ca_layout.addWidget(self.use_ca_checkbox)
        ca_group.setLayout(ca_layout)
        layout.addWidget(ca_group)

        # Private key selection
        key_group = self._create_file_selector("Your Private Key:", "key_path")
        layout.addWidget(key_group)

        # Trusted certificates (for verification)
        trusted_group = self._create_file_selector("Trusted CA Certificate (Optional):", "trusted_cert_path")
        layout.addWidget(trusted_group)

        # Output file
        output_group = self._create_file_selector("Save As:", "output_path", save=True)
        layout.addWidget(output_group)

        # Decrypt & Verify button
        decrypt_verify_btn = QPushButton("Decrypt & Verify Document")
        decrypt_verify_btn.setMinimumHeight(40)
        decrypt_verify_btn.setStyleSheet("font-size: 11pt; font-weight: bold;")
        decrypt_verify_btn.clicked.connect(self._decrypt_verify)
        layout.addWidget(decrypt_verify_btn)

        # Status
        self.status = QLabel("Ready to decrypt and verify documents")
        self.status.setStyleSheet("color: #7f8c8d; padding: 10px;")
        layout.addWidget(self.status)

        # Verification result
        result_group = QGroupBox("Verification Result:")
        result_layout = QVBoxLayout()
        self.result_display = QTextEdit()
        self.result_display.setReadOnly(True)
        self.result_display.setMinimumHeight(100)
        result_layout.addWidget(self.result_display)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        layout.addStretch()
        self.setLayout(layout)

    def _create_file_selector(self, label: str, attr: str, save: bool = False) -> QGroupBox:
        """Create a file selector group."""
        group = QGroupBox(label)
        layout = QHBoxLayout()

        field = QLineEdit()
        field.setReadOnly(True)
        setattr(self, attr, field)
        layout.addWidget(field)

        browse_btn = QPushButton("Browse...")
        if save:
            browse_btn.clicked.connect(lambda: self._browse_save(field))
        else:
            browse_btn.clicked.connect(lambda: self._browse_open(field))
        layout.addWidget(browse_btn)

        group.setLayout(layout)
        return group

    def _browse_open(self, field: QLineEdit):
        """Open file browser for opening files."""
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            field.setText(path)

    def _browse_save(self, field: QLineEdit):
        """Open file browser for saving files."""
        path, _ = QFileDialog.getSaveFileName(self, "Save As")
        if path:
            field.setText(path)

    def _decrypt_verify(self):
        """Decrypt and verify the document."""
        env_path = self.envelope_path.text()
        key_path = self.key_path.text()
        output_path = self.output_path.text()
        trusted_cert_path = self.trusted_cert_path.text()

        if not all([env_path, key_path, output_path]):
            QMessageBox.warning(self, "Missing Input", "Please select all required files.")
            return

        self.status.setText("Decrypting and verifying... please wait")
        self.status.setStyleSheet("color: #f39c12; padding: 10px;")

        def decrypt_verify_op():
            return self.service.decrypt_and_verify(
                Path(env_path),
                Path(key_path),
                Path(output_path),
                Path(trusted_cert_path) if trusted_cert_path else None
            )

        thread = WorkerThread(decrypt_verify_op, parent=self)
        thread.success.connect(
            lambda: self._on_success(f"Document decrypted and verified successfully!\nSaved to: {output_path}")
        )
        thread.error.connect(self._on_error)
        thread.finished.connect(lambda: None)
        thread.start()

    def _on_success(self, message: str):
        """Handle successful operation."""
        self.status.setText(message)
        self.status.setStyleSheet("color: #27ae60; padding: 10px;")
        self.result_display.setText("Signature verification PASSED\nDocument is authentic and unmodified.")
        QMessageBox.information(self, "Success", message)
        # Reset form
        self.envelope_path.setText("")
        self.key_path.setText("")
        self.output_path.setText("")
        self.trusted_cert_path.setText("")

    def _on_error(self, error: str):
        """Handle error."""
        self.status.setText(error)
        self.status.setStyleSheet("color: #e74c3c; padding: 10px;")
        self.result_display.setText(f"✗ Verification FAILED\n{error}")
        QMessageBox.critical(self, "Error", error)

    def _toggle_ca_usage(self):
        """Auto-fill private key from CA if available."""
        if not self.use_ca_checkbox:
            return
        if self.use_ca_checkbox.isChecked():
            if self.ca_manager and self.ca_manager.ca_exists():
                self.key_path.setText(str(self.ca_manager.ca_key_path))
                self.key_path.setReadOnly(True)
            else:
                QMessageBox.warning(self, "CA not available", "Initialize the CA in the CA tab first.")
                self.use_ca_checkbox.setChecked(False)
        else:
            self.key_path.setReadOnly(False)
            self.key_path.clear()
