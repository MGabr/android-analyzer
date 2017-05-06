import logging
import re
import subprocess

from src.definitions import CERTS_DIR

logger = logging.getLogger(__name__)


# TODO: implement user installed certificate
# TODO: deinstall

def install_as_system_certificate(emulator_id, cert):
    cert_filename = CERTS_DIR + cert.custom_ca

    # extract only certificate part - without private key
    if not cert_filename.endswith(".crt"):
        if cert_filename.endswith(".pem"):
            new_filename = cert_filename.replace(".pem", ".crt")
            cmd = "openssl x509 -inform pem -in " + cert_filename + " -out " + new_filename
            logger.debug(cmd)
            subprocess.call(cmd, shell=True)
            cert_filename = new_filename

    cmd = "openssl x509 -in " + cert_filename + " -subject_hash_old -noout"
    logger.debug(cmd)
    hashNewline = subprocess.check_output(cmd, shell=True)
    hash = re.sub(r"\W", "", hashNewline)
    sys_cert_filename = hash + ".0"

    cmd = "openssl x509 -in " + cert_filename + " >> " + sys_cert_filename
    logger.debug(cmd)
    subprocess.call(cmd, shell=True)

    cmd = "openssl x509 -in " + cert_filename + " -text -fingerprint -noout >> " + sys_cert_filename
    logger.debug(cmd)
    subprocess.call(cmd, shell=True)

    cmd = "adb -s " + emulator_id + " root"
    logger.debug(cmd)
    subprocess.call(cmd, shell=True)

    cmd = "adb -s " + emulator_id + " remount"
    logger.debug(cmd)
    subprocess.call(cmd, shell=True)

    cmd = "adb -s " + emulator_id + " push " + sys_cert_filename + " /system/etc/security/cacerts"
    logger.debug(cmd)
    subprocess.call(cmd, shell=True)

    cmd = "rm -f " + sys_cert_filename
    logger.debug(cmd)
    subprocess.call(cmd, shell=True)


def install_as_user_certificate(p12_filename):
    # TODO:
    return


# TODO: uninstall
