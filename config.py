from datetime import time



SIZE_WARNING = lambda s: int(s) > 5000
PORTS_WARNING = lambda p: p in ("22", "23", "3389")
NIGHT_ACTIVITY = lambda ts: 0 <= int(ts.split()[1][:2]) < 6
EXTERNAL_IP = lambda ip: not ip.startswith(("10.", "192.168."))



