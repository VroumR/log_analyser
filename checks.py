from reader import *
from config import *


def external_ip(load_csv):  # recois une fonction qui a elle a un appel a un fichier
    ip_external = [line[1] for line in load_csv if EXTERNAL_IP(line[1])]
    return ip_external


def sensitive_port(load_csv):
    sensitive = [line for line in load_csv if PORTS_WARNING(line[3])]
    return sensitive


def large_packets(load_csv):
    large_p = [line for line in load_csv if SIZE_WARNING(int(line[5]))]
    return large_pgit


def large_or_normal_packets(load_csv):
    l_or_n = [line + ["LARGE"] if SIZE_WARNING(int(line[5])) else line + ["NORMAL"] for line in load_csv]
    return l_or_n


def count_ip_visit(rows):
    ip_visit = {ip: sum(1 for line in rows if line[1] == ip) for ip in {line[1] for line in rows}}

    return ip_visit


def protocol_version(load_csv):
    protocol = {line[3]: line[4] for line in load_csv}
    return protocol


def suspicious_activity_per_ip(data):
    suspecious_simple_d = {
        ip: list({
            label
            for line in data
            if line[1] == ip
            for label, condition in (
                ("EXTERNAL_IP",    EXTERNAL_IP(line[1])),
                ("PORTS_WARNING",  PORTS_WARNING(line[3])),
                ("NIGHT_ACTIVITY", NIGHT_ACTIVITY(line[0])),
                ("SIZE_WARNING",   SIZE_WARNING(int(line[5]))),
            )
            if condition
        })
        for ip in {line[1] for line in data}
    }
    return suspecious_simple_d


def is_definitely_suspect(suspects):
    return{ip : suspection for ip , suspection in suspects.items() if len(suspection) >= 2 }


