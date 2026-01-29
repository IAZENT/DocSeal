"""Stylesheet for DocSeal GUI - Legacy compatibility module."""

from .themes import get_stylesheet as get_theme_stylesheet


def get_stylesheet(theme_name: str = "light") -> str:
    """Return the application stylesheet.
    
    Args:
        theme_name: "light" or "dark"
    
    Returns:
        Complete stylesheet string
    """
    return get_theme_stylesheet(theme_name)
