# in top level directory, because of path problems with subprocess calls

import subprocess


def disassemble_apk(apk_name):
    # TODO: ensure that this won't lead to command injection vulnerability when integrated in web service
    input_apk = "input_apks/" + apk_name + ".apk"
    output_path = "decoded_apks/" + apk_name
    subprocess.check_call(["./apktool", "d", "-f", input_apk, "-o", output_path])
    return output_path
