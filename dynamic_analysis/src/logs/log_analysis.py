import os
import re
import logging


logger = logging.getLogger(__name__)


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
    try:
        log_analysis_results = []
        for dynamic_analysis_result in dynamic_analysis_results:
            if dynamic_analysis_result.has_been_run and os.path.isfile(dynamic_analysis_result.get_mitm_proxy_log()):
                log_analysis_results += [LogAnalysisResult(dynamic_analysis_result, analyse_log(dynamic_analysis_result))]
            else:
                log_analysis_results += [LogAnalysisResult(dynamic_analysis_result)]
        return log_analysis_results
    except Exception as e:
        logger.exception("Crash during analysing logs")
        return []


def analyse_log(dynamic_analysis_result):
    hosts = get_hosts_w_ips(dynamic_analysis_result)

    if dynamic_analysis_result.scenario.scenario_settings.strace:
        hosts = filter_hosts_with_straced(hosts, dynamic_analysis_result)
    else:
        hosts = {host for (host, ip) in hosts}

    return hosts


def get_hosts_w_ips(dynamic_analysis_result):
    mitm_proxy = open(dynamic_analysis_result.get_mitm_proxy_log(), "r")

    hosts = set()

    host_ip_regex = r"^host: (?P<host>.*),ip: (?P<ip>.*)$"
    url_regex = r"^url: (.*)$"

    http_host_ip_regex = r"^http host: (?P<host>.*),ip: (?P<ip>.*)$"
    http_url_regex = r"http url: (.*)$"

    for line in mitm_proxy:
        match = re.match(host_ip_regex, line)
        if match:
            host = match.group("host")
            ip = match.group("ip")
            hosts |= {(host, ip)}

        if dynamic_analysis_result.scenario.scenario_settings.report_http:
            match = re.match(http_host_ip_regex, line)
            if match:
                host = match.group("host")
                ip = match.group("ip")
                hosts |= {(host, ip)}

    mitm_proxy.close()
    os.remove(mitm_proxy.name)

    return hosts


def filter_hosts_with_straced(hosts, dynamic_analysis_result):
    network = open(dynamic_analysis_result.get_network_monitor_log(), "r")

    app_ips = set()

    ip_regex = r".*\"(::ffff:)?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\".*" # ::ffff: for ip4_to_6 addresses

    for line in network:
        match = re.match(ip_regex, line)
        if match:
            app_ips |= {match.group("ip")}

    network.close()
    os.remove(network.name)

    return {host for (host, ip) in hosts if ip in app_ips}
