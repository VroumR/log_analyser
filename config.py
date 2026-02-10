from datetime import time



SIZE_WARNING = lambda s : s > 5000
PORTS_WARNING = lambda w : w in ("22","23","3389")
NIGHT_ACTIVITY = lambda t: 0 <= int(t.split(" ")[1][:2]) < 6
EXTERNAL_IP = lambda ip : not  ip.startswith(("10.", "192.168."))


