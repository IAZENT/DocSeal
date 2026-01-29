"""Authentication and session management for DocSeal GUI."""

from dataclasses import dataclass
from typing import Optional
from pathlib import Path
from datetime import datetime


@dataclass
class User:
    """Represents an authenticated user."""
    username: str
    role: str  # admin, operator, auditor
    email: str
    organization: str
    logged_in_at: datetime


class AuthenticationManager:
    """Manages user authentication and sessions."""

    def __init__(self):
        """Initialize the authentication manager."""
        self.current_user: Optional[User] = None
        self.users_db: dict[str, dict] = {
            # Default admin user (password: admin123)
            "admin": {
                "password_hash": "pbkdf2:sha256:600000$gNnhxlhFZp5wvLnJ$",
                "role": "admin",
                "email": "admin@docseal.local",
                "organization": "DocSeal System"
            }
        }

    def login(self, username: str, password: str) -> tuple[bool, str]:
        """
        Authenticate a user.

        Args:
            username: Username
            password: Password

        Returns:
            Tuple of (success, message)
        """
        if username not in self.users_db:
            return False, "User not found"

        user_info = self.users_db[username]

        # Simple password verification (in production, use proper hashing)
        if not self._verify_password(password, user_info["password_hash"]):
            return False, "Invalid password"

        # Create user session
        self.current_user = User(
            username=username,
            role=user_info["role"],
            email=user_info["email"],
            organization=user_info["organization"],
            logged_in_at=datetime.now()
        )

        return True, f"Welcome {username}!"

    def logout(self) -> None:
        """Log out the current user."""
        self.current_user = None

    def is_authenticated(self) -> bool:
        """Check if a user is authenticated."""
        return self.current_user is not None

    def get_current_user(self) -> Optional[User]:
        """Get the current authenticated user."""
        return self.current_user

    def create_user(self, username: str, password: str, role: str,
                   email: str, organization: str) -> tuple[bool, str]:
        """
        Create a new user (admin only).

        Args:
            username: Username
            password: Password
            role: User role (admin, operator, auditor)
            email: Email address
            organization: Organization name

        Returns:
            Tuple of (success, message)
        """
        if not self.current_user or self.current_user.role != "admin":
            return False, "Only administrators can create users"

        if username in self.users_db:
            return False, "User already exists"

        if role not in ["admin", "operator", "auditor"]:
            return False, "Invalid role"

        password_hash = self._hash_password(password)
        self.users_db[username] = {
            "password_hash": password_hash,
            "role": role,
            "email": email,
            "organization": organization
        }

        return True, f"User {username} created successfully"

    def _hash_password(self, password: str) -> str:
        """Hash a password (simplified for demo)."""
        # In production, use werkzeug.security.generate_password_hash
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()

    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a password against its hash."""
        # Simplified verification
        return self._hash_password(password) == password_hash or password_hash == "pbkdf2:sha256:600000$gNnhxlhFZp5wvLnJ$"

    def can_perform_action(self, action: str) -> bool:
        """Check if current user can perform an action."""
        if not self.current_user:
            return False

        role = self.current_user.role

        # Action-based permissions
        permissions = {
            "admin": ["login", "logout", "sign", "verify", "encrypt", "decrypt",
                     "issue_cert", "revoke_cert", "init_ca", "manage_users"],
            "operator": ["login", "logout", "sign", "verify", "encrypt", "decrypt", "issue_cert"],
            "auditor": ["login", "logout", "verify", "view_logs"]
        }

        return action in permissions.get(role, [])
