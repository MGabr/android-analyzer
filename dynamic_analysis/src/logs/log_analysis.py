import os
import re


class LogAnalysisResult:
    def __init__(self, dynamic_analysis_result, connected_hosts=None):
        self.dynamic_analysis_result = dynamic_analysis_result
        self.connected_hosts = connected_hosts

        self.is_vulnerable = bool(self.connected_hosts)
        self.is_statically_vulnerable = bool(self.dynamic_analysis_result.is_statically_vulnerable)

    def __json__(self):
        return {
            'dynamic_analysis_result': self.dynamic_analysis_result,
            'connected_hosts': list(self.connected_hosts) if self.connected_hosts else None,
            'is_vulnerable': self.is_vulnerable,
            'is_statically_vulnerable': self.is_statically_vulnerable}


def analyse_logs(dynamic_analysis_results):
    log_analysis_results = []
    for dynamic_analysis_result in dynamic_analysis_results:
        if dynamic_analysis_result.has_been_run and os.path.isfile(dynamic_analysis_result.get_mitm_proxy_log()):
            log_analysis_results += [LogAnalysisResult(dynamic_analysis_result, analyse_log(dynamic_analysis_result))]
        else:
            log_analysis_results += [LogAnalysisResult(dynamic_analysis_result)]
    return log_analysis_results


def analyse_log(dynamic_analysis_result):
    mitm_proxy = open(dynamic_analysis_result.get_mitm_proxy_log(), "r")
    # network = open(dynamic_analysis_result.get_network_monitor_log(), "r")

    host_regex = r"^host: (.*)$"
    url_regex = r"^url: (.*)$"
    ip_regex = r"^ip: (.*)$"

    hosts = set()
    urls = set()
    ips = set()
    for line in mitm_proxy:

        host = re.findall(host_regex, line)
        if host:
            hosts |= set(host)

        url = re.findall(url_regex, line)
        if url:
            urls |= set(url)

    # connected_ips = set()
    # for line in network:
    #     for ip in ips:
    #         ip_regex = r".*" + ip + r".*" # TODO: escape dots
    #         if re.match(ip_regex, line):
    #             connected_ips |= {ip}

    print "connected_hosts: " + str(hosts)

    mitm_proxy.close()
    os.remove(mitm_proxy.name)
    # network.close()
    # os.remove(network.name)

    return hosts
