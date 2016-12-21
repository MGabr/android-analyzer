# TODO: different cases
# self-signed, on-the-fly mitmproxy?
# signed by invalid CA, mitmproxy on the fly CA
# expired?

# valid certificate with other hostname, mitmproxy custom valid certificate

# invalid certificate with other hostname, mitmproxy custom invalid certificate

import subprocess
import logging


logger = logging.getLogger(__name__)


def start_mitm_proxy():
    cmd = "mitmproxy -w mitmproxy -q --port 8080"
    process = subprocess.Popen(cmd, shell=True)
    logger.debug("mitm_proxy started")
    return process


def kill_mitm_proxy(mitm_proxy_process):
    mitm_proxy_process.kill()
