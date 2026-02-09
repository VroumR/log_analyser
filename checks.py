from reader import *










def external_ip(load_csv):         #recois une fonction qui a elle a un appel a un fichier
    ip_external = [line[1] for line in load_csv if not line[1].startswith("192.168") and not line[1].startswith("10.")]
    return ip_external
print(external_ip(load_csv("network_traffic.log")))