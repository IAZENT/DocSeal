"""Terminal color support for CLI output."""

import sys


class Colors:
    """ANSI color codes for terminal output."""

    # Check if output is a TTY
    ENABLED = sys.stdout.isatty()

    # Color codes
    GREEN = "\033[92m" if ENABLED else ""
    RED = "\033[91m" if ENABLED else ""
    YELLOW = "\033[93m" if ENABLED else ""
    BLUE = "\033[94m" if ENABLED else ""
    CYAN = "\033[96m" if ENABLED else ""
    BOLD = "\033[1m" if ENABLED else ""
    RESET = "\033[0m" if ENABLED else ""

    @classmethod
    def success(cls, text: str) -> str:
        """Return text in green (success)."""
        return f"{cls.GREEN}{text}{cls.RESET}"

    @classmethod
    def error(cls, text: str) -> str:
        """Return text in red (error)."""
        return f"{cls.RED}{text}{cls.RESET}"

    @classmethod
    def warning(cls, text: str) -> str:
        """Return text in yellow (warning)."""
        return f"{cls.YELLOW}{text}{cls.RESET}"

    @classmethod
    def info(cls, text: str) -> str:
        """Return text in blue (info)."""
        return f"{cls.BLUE}{text}{cls.RESET}"

    @classmethod
    def bold(cls, text: str) -> str:
        """Return text in bold."""
        return f"{cls.BOLD}{text}{cls.RESET}"
