# in top level directory, because of path problems with subprocess calls

import subprocess
from definitions import INPUT_APK_DIR, DECODED_APK_DIR

def disassemble_apk(apk_name):
    # TODO: ensure that this won't lead to command injection vulnerability when integrated in web service
    input_apk = INPUT_APK_DIR + apk_name + ".apk"
    output_path = DECODED_APK_DIR + apk_name
    subprocess.check_call(["./apktool", "d", "-f", input_apk, "-o", output_path])
    return output_path
