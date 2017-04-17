# in top level directory, because of path problems with subprocess calls

import subprocess
import logging
import os

from src.definitions import INPUT_APK_DIR, DECODED_APK_DIR


logger = logging.getLogger(__name__)
DIR = os.path.dirname(os.path.abspath(__file__))


def disassemble_apk(apk_name):
    # TODO: ensure that this won't lead to command injection vulnerability when integrated in web service
    input_apk = INPUT_APK_DIR + apk_name + ".apk"
    output_path = DECODED_APK_DIR + apk_name
    cmd = DIR + "/apktool d -f " + input_apk + " -o " + output_path
    logger.debug(cmd)
    subprocess.check_call(cmd, shell=True)
    return output_path
