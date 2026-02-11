from checks import *
from config import *
from reader import *


def lst_of_howers(data):
    return list(map(lambda row: int(row[0].split()[1].split(":")[0]), data))


def size_in_bytes(data):
    return list(map(lambda row : round(int(row[5])/1024,1), data))

def dangerous_port(data):
    return list(filter(lambda l : PORTS_WARNING(l[3]), data))

def dangerous_night(data):
    return list(filter(lambda h : NIGHT_ACTIVITY(h[0]), data))

suspicion_checks = {
    "EXTERNAL_IP":    lambda r: EXTERNAL_IP(r[1]),     # source IP
    "SIZE_WARNING":   lambda r: SIZE_WARNING(r[5]),    # size
    "NIGHT_ACTIVITY": lambda r: NIGHT_ACTIVITY(r[0]),  # timestamp
    "PORTS_WARNING":  lambda r: PORTS_WARNING(r[3])    # port (pas protocol)
}



def get_matching_suspicions(line , suspicion_checks ):
        return list(
            map(
                lambda item: item[0],
                filter(
                    lambda item: item[1](line),
                    suspicion_checks.items()
                )
            )
        )


print(get_matching_suspicions(load_csv("network_traffic.log")[11],suspicion_checks))


