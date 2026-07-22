"""
Notifications Module
=====================
Copyright (c) 2026 Rishabh Joshi

Provides zero-dependency cross-platform desktop notifications.
Uses native AppleScript on macOS and notify-send on Linux.
"""

import subprocess
import sys

def notify(title: str, message: str) -> None:
    """
    Triggers a native system desktop notification.

    Args:
        title (str): Title header of the desktop banner.
        message (str): Body description text of the notification banner.
    """
    safe_title = title.replace('"', '\\"')
    safe_msg = message.replace('"', '\\"')
    
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

