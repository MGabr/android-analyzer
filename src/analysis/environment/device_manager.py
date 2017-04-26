import subprocess
import time
import logging


logger = logging.getLogger(__name__)


def get_emulator():
    # TODO: maybe use -gpu on
    no_audio = "export QEMU_AUDIO_DRV=none && "
    emulator_type = "Nexus_5_API_24" # currently only this fixed emulator supported
    port = "5554"
    other_opts = "-wipe-data -use-system-libs -writable-system -no-boot-anim -http-proxy http://0.0.0.0:8080"
    cmd = no_audio + "emulator -avd " + emulator_type + " -port " + port + " " + other_opts + "  &"
    logger.debug(cmd)
    subprocess.check_call(cmd, shell=True)
    emulator_id = "emulator-" + port
    wait_until_boot_completed(emulator_id)

    return emulator_id


def wait_until_boot_completed(emulator_id):
    cmd = "adb -s " + emulator_id + " wait-for-device shell getprop sys.boot_completed"
    while "1" not in subprocess.check_output(cmd, shell=True):
        time.sleep(1)


def return_emulator(emulator_id):
    # TODO: not working because of telnet auth token
    cmd = "adb -s " + emulator_id + " emu kill"
    subprocess.call(cmd, shell=True)
