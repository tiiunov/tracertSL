from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1
import sys
import json
import urllib.request


def get_as_country_provider(ip):
    answer = urllib.request.urlopen(f'https://ipinfo.io/{ip}/json')
    answer_dict = json.loads(answer.read())
    a_sys = country = provider = "grey IP"
    try:
        country = answer_dict["country"]
        a_sys_and_provider = answer_dict["org"].split(' ', 1)
        a_sys = a_sys_and_provider[0]
        provider = a_sys_and_provider[1]
    except KeyError:
        pass
    return a_sys, country, provider


if len(sys.argv) > 1:
    hostname = sys.argv[1]
else:
    hostname = "vk.com"
for i in range(1, 30):
    packet = IP(dst=hostname, ttl=i) / ICMP()
    reply = sr1(packet, verbose=0, timeout=25)
    if reply is None:
        print(f"answer № {i} --------- timeout")
        continue
    elif reply.type == 0:
        current_ip = reply.src
        a_sys, country, provider = get_as_country_provider(current_ip)
        print(f"Finally, answer № {i} from {current_ip}   AS:{a_sys}   Country:{country}   Provider:{provider}")
        print("That's all:)")
        break
    else:
        current_ip = reply.src
        a_sys, country, provider = get_as_country_provider(current_ip)
        print(f"answer № {i} from {current_ip}   AS:{a_sys}   Country:{country}   Provider:{provider}")
