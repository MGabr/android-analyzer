import subprocess
import logging
import shlex


logger = logging.getLogger(__name__)


def start_mitm_proxy(certificate, log_id):
    cmd = "mitmproxy -w mitm_proxy_log" + str(log_id) + " -q --port 8080"
    if certificate.custom_ca:
        cmd += " --cadir "
    if certificate.custom_cert:
        if certificate.custom_cert_domain:
            cmd += " --cert " + certificate.custom_cert_domain + "=" + certificate.custom_cert
        else:
            cmd += " --cert *=" + certificate.custom_cert

    logger.debug(cmd)
    process = subprocess.Popen(shlex.split(cmd))
    return process


def kill_mitm_proxy(mitm_proxy_process):
    mitm_proxy_process.kill()
