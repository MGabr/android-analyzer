import logging
import os
import re

from common.dto.dynamic_analysis import LogAnalysisResult
from src.definitions import LOGS_DIR


logger = logging.getLogger(__name__)


def analyse_log(dynamic_analysis_result):
    try:
        hosts = get_hosts_w_ips(dynamic_analysis_result)

        if dynamic_analysis_result.scenario.scenario_settings.strace:
            hosts = filter_hosts_with_straced(hosts, dynamic_analysis_result)
        else:
            hosts = {host for (host, ip) in hosts}

        return LogAnalysisResult(dynamic_analysis_result, hosts)
    except Exception:
        logger.exception("Crash during analysing logs")
        return LogAnalysisResult(dynamic_analysis_result)


def get_hosts_w_ips(dynamic_analysis_result):
    mitm_proxy = open(LOGS_DIR + "mitm_proxy_log" + str(dynamic_analysis_result.log_id), "r")

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
    network = open(LOGS_DIR + "network_monitor_log" + str(dynamic_analysis_result.log_id), "r")

    app_ips = set()

    ip_regex = r".*\"(::ffff:)?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\".*" # ::ffff: for ip4_to_6 addresses

    for line in network:
        match = re.match(ip_regex, line)
        if match:
            app_ips |= {match.group("ip")}

    network.close()
    os.remove(network.name)

    for host, ip in hosts:
        logger.warn("host: " + host + ", ip: " + ip)
    for app_ip in app_ips:
        logger.warn("app_ip: " + app_ip)

    return {host for host, ip in hosts if ip in app_ips}
