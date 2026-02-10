from reader import *
from config import *



def external_ip(load_csv):         #recois une fonction qui a elle a un appel a un fichier
    ip_external = [line[1] for line in load_csv if not line[1].startswith("192.168") and not line[1].startswith("10.")]
    return ip_external


def sensitive_port(load_csv):
    sensitive = [line for line in load_csv for n in PORTS_WARNING if line[3] == n ]
    return sensitive




def large_packets(load_csv):
    large_p = [line for line in load_csv if int(line[5]) > SIZE_WARNING ]
    return large_p



def large_or_normal_packets(load_csv):
    l_or_n = [line+["LARGE"] if int(line[5]) > SIZE_WARNING  else line+["NORMAL"] for line in load_csv]
    return l_or_n


def count_ip_visit(rows):

    ip_visit = {ip: sum(1 for line in rows if line[1] == ip) for ip in {line[1] for line in rows}}

    return ip_visit

def protocol_version(load_csv):
    protocol = {line[3]:line[4] for line in load_csv}
    return protocol

