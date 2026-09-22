"""
Notifications Module
=====================
Copyright (c) 2026 Rishabh Joshi

Provides zero-dependency cross-platform desktop notifications.
Uses native AppleScript on macOS and notify-send on Linux.
"""

import subprocess
import sys


def _applescript_escape(s: str) -> str:
    # Escape backslashes FIRST, then quotes. Reversing the order (or
    # skipping backslashes) lets a trailing "\" escape the closing quote
    # and break out of the AppleScript string literal.
    return s.replace("\\", "\\\\").replace('"', '\\"')


def notify(title: str, message: str) -> None:
    """
    Triggers a native system desktop notification.

    Args:
        title (str): Title header of the desktop banner.
        message (str): Body description text of the notification banner.
    """
    safe_title = _applescript_escape(title)
    safe_msg = _applescript_escape(message)
    
    if sys.platform == "darwin":
        cmd = f'display notification "{safe_msg}" with title "{safe_title}" sound name "Glass"'
        try:
            subprocess.run(["osascript", "-e", cmd], check=True)
            return
        except Exception:
            pass
            
    elif sys.platform.startswith("linux"):
        try:
            subprocess.run(["notify-send", title, message], check=True)
            return
        except Exception:
            pass

    print(f"\n[ALERT NOTIFICATION] {title}: {message}\n")

