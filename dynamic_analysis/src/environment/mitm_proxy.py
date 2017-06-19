import logging
import shlex
import os

import subprocess32 as subprocess

from src.definitions import LOGS_DIR, CERTS_DIR, SCRIPTS_DIR

logger = logging.getLogger(__name__)


class MitmProxy:
    def __init__(self, certificate, add_upstream_certs, log_id):
        self.process = None
        self.text_to_file_safer = TextToFileSafer()

        self.certificate = certificate
        self.add_upstream_certs = add_upstream_certs
        self.log_id = log_id

    def __enter__(self):
        self.start()

    def start(self):
        cmd = "mitmdump -q -dd -s '{scripts_dir}log.py {logs_dir}mitm_proxy_log{log_id}' --port 8080".format(
            scripts_dir=SCRIPTS_DIR,
            logs_dir=LOGS_DIR,
            log_id=self.log_id)

        if self.certificate.custom_ca:
            filepath = "{certs_dir}mitmproxy-ca.pem".format(certs_dir=CERTS_DIR)
            self.text_to_file_safer.save(self.certificate.custom_ca, filepath)
            cmd += " --cadir " + CERTS_DIR

        if self.certificate.custom_cert:
            filepath = "{certs_dir}custom_cert.pem".format(certs_dir=CERTS_DIR)
            self.text_to_file_safer.save(self.certificate.custom_cert, filepath)
            if self.certificate.custom_cert_domain:
                cmd += " --cert {domain}={filep}".format(domain=self.certificate.custom_cert_domain, filep=filepath)
            else:
                cmd += " --cert *=" + filepath

        if self.add_upstream_certs:
            cmd += " --add-upstream-certs-to-client-chain --insecure"

        logger.debug(cmd)
        self.process = subprocess.Popen(shlex.split(cmd))

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.kill()

    def kill(self):
        if self.process:
            self.process.kill()
            self.process.communicate(input="y\n")
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired as e:
                logger.exception("Could not close network monitor")
            except OSError as e:
                logger.warn(e)


class TextToFileSafer:
    def __init__(self):
        self.saved_filepaths = []

    def save(self, text, filepath):
        with open(filepath, "w+") as saved_file:
            saved_file.write(text)
            self.saved_filepaths += [filepath]

    def remove_all(self):
        for filepath in self.saved_filepaths:
            os.remove(filepath)
        self.saved_filepaths = []
