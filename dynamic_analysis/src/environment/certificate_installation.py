import logging
import os
import re
import subprocess

from src.definitions import CERTS_DIR


logger = logging.getLogger(__name__)


class InstalledCertificates:
    def __init__(self, emulator_id, certificates_to_install):
        self.installed_certificates_filenames = []
        self.emulator_id = emulator_id
        self.certificates_to_install = certificates_to_install

    def __enter__(self):
        self.install_all()

    def install_all(self):
        if self.certificates_to_install:
            try:
                while True:
                    certificate_to_install = self.certificates_to_install.pop()
                    installed_filename = install_as_system_certificate(self.emulator_id, certificate_to_install)
                    self.installed_certificates_filenames += [installed_filename]
            except IndexError:
                # list is now empty
                pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.uninstall_all()

    def uninstall_all(self):
        if self.installed_certificates_filenames:
            try:
                while True:
                    filename = self.installed_certificates_filenames.pop()
                    uninstall_system_certificate(self.emulator_id, filename)
            except IndexError:
                # list is now empty
                pass


def install_as_system_certificate(emulator_id, cert):

    # extract only certificate part - without private key
    cert_filename = CERTS_DIR + 'installed_cert.pem'
    with open(cert_filename, 'w') as cert_file:
        cert_file.write(cert.custom_ca)
    new_filename = cert_filename.replace(".pem", ".crt")
    cmd = "openssl x509 -inform pem -in " + cert_filename + " -out " + new_filename
    logger.debug(cmd)
    subprocess.check_call(cmd, shell=True)
    os.remove(cert_filename)
    cert_filename = new_filename

    cmd = "openssl x509 -in " + cert_filename + " -subject_hash_old -noout"
    logger.debug(cmd)
    hashNewline = subprocess.check_output(cmd, shell=True)
    hash = re.sub(r"\W", "", hashNewline)
    sys_cert_filename = hash + ".0"

    cmd = "openssl x509 -in " + cert_filename + " >> " + sys_cert_filename
    logger.debug(cmd)
    subprocess.check_call(cmd, shell=True)

    cmd = "openssl x509 -in " + cert_filename + " -text -fingerprint -noout >> " + sys_cert_filename
    logger.debug(cmd)
    subprocess.check_call(cmd, shell=True)
    os.remove(cert_filename)

    cmd = "adb -s " + emulator_id + " root"
    logger.debug(cmd)
    subprocess.check_call(cmd, shell=True)

    cmd = "adb -s " + emulator_id + " remount"
    logger.debug(cmd)
    subprocess.check_call(cmd, shell=True)

    cmd = "adb -s " + emulator_id + " push " + sys_cert_filename + " /system/etc/security/cacerts"
    logger.debug(cmd)
    subprocess.check_call(cmd, shell=True)

    # use this instead of os.remove(), so we don't have to care in which path cmd's are executed
    cmd = "rm -f " + sys_cert_filename
    logger.debug(cmd)
    subprocess.check_call(cmd, shell=True)

    return sys_cert_filename


def uninstall_system_certificate(emulator_id, installed_cert_filename):
    try:
        cmd = "adb -s " + emulator_id + " shell rm /system/etc/security/cacerts/" + installed_cert_filename
        logger.debug(cmd)
        subprocess.check_call(cmd, shell=True)
    except Exception:
        logger.exception("Could not uninstall system certificate")


def install_as_user_certificate(p12_filename):
    # TODO:
    return


# TODO: uninstall
