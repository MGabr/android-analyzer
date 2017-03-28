# in top level directory, because of path problems with subprocess calls

import subprocess
import logging
import shlex


logger = logging.getLogger(__name__)


def start_mitm_proxy(certificate, log_id):
    cmd = "mitmproxy -w logs/mitm_proxy_log" + str(log_id) + " --port 8080"
    if certificate.custom_ca:
        prev_cmd = "cp " + certificate.custom_ca + " mitmproxy/mitmproxy-ca.pem"
        logger.debug(prev_cmd)
        subprocess.call(prev_cmd, shell=True)

        cmd += " --cadir ./mitmproxy"
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
    mitm_proxy_process.communicate(input="y\n")
