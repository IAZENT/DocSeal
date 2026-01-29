"""Theme system for DocSeal GUI with light and dark modes."""


class Theme:
    """Base theme class."""

    # Primary colors
    primary_bg: str
    primary_text: str
    secondary_bg: str
    secondary_text: str
    
    # UI element colors
    button_bg: str
    button_text: str
    button_hover: str
    button_pressed: str
    
    # Input field colors
    input_bg: str
    input_text: str
    input_border: str
    input_focus_border: str
    
    # Status colors
    success_bg: str
    success_text: str
    error_bg: str
    error_text: str
    warning_bg: str
    warning_text: str
    
    # Other elements
    sidebar_bg: str
    sidebar_text: str
    label_text: str
    border_color: str
    
    @staticmethod
    def get_stylesheet(theme: 'Theme') -> str:
        """Generate complete stylesheet for theme."""
        return f"""
        QMainWindow {{
            background-color: {theme.primary_bg};
        }}

        QWidget {{
            background-color: {theme.primary_bg};
            color: {theme.primary_text};
        }}

        QLabel {{
            color: {theme.label_text};
        }}

        QPushButton {{
            background-color: {theme.button_bg};
            color: {theme.button_text};
            border: none;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
            font-size: 10pt;
        }}

        QPushButton:hover {{
            background-color: {theme.button_hover};
        }}

        QPushButton:pressed {{
            background-color: {theme.button_pressed};
        }}

        QPushButton:disabled {{
            background-color: {theme.border_color};
            color: {theme.secondary_text};
        }}

        QLineEdit {{
            background-color: {theme.input_bg};
            color: {theme.input_text};
            border: 1px solid {theme.input_border};
            border-radius: 4px;
            padding: 6px 10px;
            font-size: 10pt;
        }}

        QLineEdit:focus {{
            border: 2px solid {theme.input_focus_border};
        }}

        QLineEdit::placeholder {{
            color: {theme.secondary_text};
        }}

        QTextEdit {{
            background-color: {theme.input_bg};
            color: {theme.input_text};
            border: 1px solid {theme.input_border};
            border-radius: 4px;
            padding: 6px 10px;
            font-size: 10pt;
        }}

        QTextEdit:focus {{
            border: 2px solid {theme.input_focus_border};
        }}

        QComboBox {{
            background-color: {theme.input_bg};
            color: {theme.input_text};
            border: 1px solid {theme.input_border};
            border-radius: 4px;
            padding: 6px 10px;
            font-size: 10pt;
        }}

        QComboBox:focus {{
            border: 2px solid {theme.input_focus_border};
        }}

        QComboBox::drop-down {{
            border: none;
            background-color: {theme.button_bg};
        }}

        QComboBox QAbstractItemView {{
            background-color: {theme.input_bg};
            color: {theme.input_text};
            selection-background-color: {theme.button_bg};
        }}

        QGroupBox {{
            border: 1px solid {theme.input_border};
            border-radius: 4px;
            margin-top: 10px;
            padding-top: 10px;
            font-weight: bold;
            color: {theme.label_text};
        }}

        QGroupBox::title {{
            subcontrol-origin: margin;
            subcontrol-position: top left;
            left: 10px;
        }}

        QProgressBar {{
            border: 1px solid {theme.input_border};
            border-radius: 4px;
            text-align: center;
            color: {theme.input_text};
            background-color: {theme.input_bg};
        }}

        QProgressBar::chunk {{
            background-color: {theme.success_bg};
        }}

        QMessageBox {{
            background-color: {theme.primary_bg};
        }}

        QMessageBox QLabel {{
            color: {theme.primary_text};
        }}

        QMessageBox QPushButton {{
            min-width: 60px;
        }}

        QTabWidget::pane {{
            border: 1px solid {theme.input_border};
        }}

        QTabBar::tab {{
            background-color: {theme.secondary_bg};
            color: {theme.secondary_text};
            padding: 8px 20px;
            border: 1px solid {theme.input_border};
        }}

        QTabBar::tab:selected {{
            background-color: {theme.button_bg};
            color: {theme.button_text};
        }}

        QScrollBar:vertical {{
            border: none;
            background-color: {theme.secondary_bg};
            width: 12px;
            margin: 0px 0px 0px 0px;
        }}

        QScrollBar::handle:vertical {{
            background-color: {theme.button_bg};
            border-radius: 6px;
            min-height: 0px;
        }}

        QScrollBar::handle:vertical:hover {{
            background-color: {theme.button_hover};
        }}

        QScrollBar:horizontal {{
            border: none;
            background-color: {theme.secondary_bg};
            height: 12px;
            margin: 0px 0px 0px 0px;
        }}

        QScrollBar::handle:horizontal {{
            background-color: {theme.button_bg};
            border-radius: 6px;
            min-width: 0px;
        }}

        QScrollBar::handle:horizontal:hover {{
            background-color: {theme.button_hover};
        }}

        QSpinBox, QDoubleSpinBox {{
            background-color: {theme.input_bg};
            color: {theme.input_text};
            border: 1px solid {theme.input_border};
            border-radius: 4px;
            padding: 4px 8px;
        }}

        QCheckBox, QRadioButton {{
            color: {theme.primary_text};
            spacing: 5px;
        }}

        QCheckBox::indicator, QRadioButton::indicator {{
            width: 18px;
            height: 18px;
        }}

        QCheckBox::indicator:unchecked {{
            background-color: {theme.input_bg};
            border: 1px solid {theme.input_border};
        }}

        QCheckBox::indicator:checked {{
            background-color: {theme.button_bg};
            border: 1px solid {theme.button_bg};
        }}
        """


class LightTheme(Theme):
    """Light theme for DocSeal GUI."""

    # Primary colors
    primary_bg = "#f5f6fa"
    primary_text = "#2c3e50"
    secondary_bg = "#ecf0f1"
    secondary_text = "#7f8c8d"
    
    # UI element colors
    button_bg = "#3498db"
    button_text = "#ffffff"
    button_hover = "#2980b9"
    button_pressed = "#1f618d"
    
    # Input field colors
    input_bg = "#ffffff"
    input_text = "#2c3e50"
    input_border = "#bdc3c7"
    input_focus_border = "#3498db"
    
    # Status colors
    success_bg = "#2ecc71"
    success_text = "#ffffff"
    error_bg = "#e74c3c"
    error_text = "#ffffff"
    warning_bg = "#f39c12"
    warning_text = "#ffffff"
    
    # Other elements
    sidebar_bg = "#2c3e50"
    sidebar_text = "#ecf0f1"
    label_text = "#2c3e50"
    border_color = "#bdc3c7"


class DarkTheme(Theme):
    """Dark theme for DocSeal GUI."""

    # Primary colors
    primary_bg = "#1a1a1a"
    primary_text = "#e0e0e0"
    secondary_bg = "#2d2d2d"
    secondary_text = "#a0a0a0"
    
    # UI element colors
    button_bg = "#0088cc"
    button_text = "#ffffff"
    button_hover = "#0066aa"
    button_pressed = "#004488"
    
    # Input field colors
    input_bg = "#2d2d2d"
    input_text = "#e0e0e0"
    input_border = "#404040"
    input_focus_border = "#0088cc"
    
    # Status colors
    success_bg = "#22aa44"
    success_text = "#ffffff"
    error_bg = "#dd3333"
    error_text = "#ffffff"
    warning_bg = "#ff9933"
    warning_text = "#000000"
    
    # Other elements
    sidebar_bg = "#0d0d0d"
    sidebar_text = "#e0e0e0"
    label_text = "#e0e0e0"
    border_color = "#404040"


# Theme registry
THEMES = {
    "light": LightTheme(),
    "dark": DarkTheme(),
}


def get_theme(name: str = "light") -> Theme:
    """Get theme by name."""
    return THEMES.get(name.lower(), LightTheme())


def get_stylesheet(theme_name: str = "light") -> str:
    """Get stylesheet for theme."""
    theme = get_theme(theme_name)
    return Theme.get_stylesheet(theme)
