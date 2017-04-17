import logging
import shlex

import subprocess32 as subprocess

from src.definitions import LOGS_DIR, CERTS_DIR

logger = logging.getLogger(__name__)


def start_mitm_proxy(certificate, log_id):
    cmd = "mitmproxy -w {logs_dir}mitm_proxy_log{log_id} --port 8080".format(logs_dir=LOGS_DIR, log_id=log_id)
    if certificate.custom_ca:
        prev_cmd = "cp {certs_dir}{custom_ca} {certs_dir}/mitmproxy-ca.pem".format(
            certs_dir=CERTS_DIR,
            custom_ca=certificate.custom_ca)
        logger.debug(prev_cmd)
        subprocess.call(prev_cmd, shell=True)

        cmd += " --cadir " + CERTS_DIR
    if certificate.custom_cert:
        if certificate.custom_cert_domain:
            cmd += " --cert {domain}={certs_dir}{custom_cert}".format(
                domain=certificate.custom_cert_domain,
                certs_dir=CERTS_DIR,
                custom_cert=certificate.custom_cert)
        else:
            cmd += " --cert *=" + CERTS_DIR + certificate.custom_cert

    logger.debug(cmd)
    process = subprocess.Popen(shlex.split(cmd))
    return process


def kill_mitm_proxy(mitm_proxy_process):
    mitm_proxy_process.kill()
    mitm_proxy_process.communicate(input="y\n")
    try:
        mitm_proxy_process.wait(timeout=10)
    except subprocess.TimeoutExpired as e:
        logger.error("Could not close network monitor: {}", e)
    except OSError as e:
        logger.warn(e)

