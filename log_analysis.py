import re


class LogAnalysisResult:
    def __init__(self, connected_ips):
        self.connected_ips = connected_ips


def analyse_log():
    mitm_proxy = open("mitmproxy", "r")
    network = open("network_emulator-5554", "r")

    ssl_regex = r"ssl_established,4:true"
    between_ssl_ip_regex = r"(?!ssl_established).*address,[0-9]{1,2}:[0-9]{1,2}:address,[0-9]{1,2}:[0-9]{1,2}:"
    ip_regex = r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
    get_ip_regex = ssl_regex + between_ssl_ip_regex + ip_regex

    ips = set()
    for line in mitm_proxy:
        if re.findall(get_ip_regex, line):
            print "regex: " + str(re.findall(get_ip_regex, line)) + ", line: " + line
        ips |= set(re.findall(get_ip_regex, line))

    print "ips: " + str(ips)

    connected_ips = set()
    for line in network:
        for ip in ips:
            ip_regex = r".*" + ip + r".*" # TODO: escape dots
            if re.match(ip_regex, line):
                connected_ips |= {ip}

    print "connected_ips: " + str(connected_ips)
    return LogAnalysisResult(connected_ips)


if __name__ == "__main__":
    analyse_log()