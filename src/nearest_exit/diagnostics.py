from __future__ import annotations

import re
import shutil
import subprocess
import sys


def detect_vpn() -> str | None:
    """Return interface or gateway string if the default route looks VPN-routed."""
    try:
        if sys.platform == "darwin":
            out = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=2,
            ).stdout
            iface = re.search(r"interface:\s*(\S+)", out)
            gw = re.search(r"gateway:\s*(\S+)", out)
            if iface and re.match(r"(utun|tun|tap|ppp|wg)", iface.group(1)):
                return iface.group(1)
            if gw and re.match(
                r"(10\.|100\.6[4-9]\.|100\.[7-9]\d\.|100\.1[01]\d\.|100\.12[0-7]\.)",
                gw.group(1),
            ):
                return gw.group(1)
        elif sys.platform.startswith("linux"):
            out = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=2,
            ).stdout
            m = re.search(r"dev\s+(\S+)", out)
            if m and re.match(r"(tun|tap|wg|ppp)", m.group(1)):
                return m.group(1)
    except Exception:
        pass
    return None


def ping_available() -> bool:
    return shutil.which("ping") is not None
