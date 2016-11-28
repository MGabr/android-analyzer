import subprocess


def disassemble_apk(apk_path):
    # TODO: ensure that this won't lead to command injection vulnerability when integrated in web service
    apk_name = apk_path.split(".apk")[0].split("/")[-1]
    subprocess.check_call(["./apktool", "d", "-f", apk_path, "-o", "decoded_apks/" + apk_name])
