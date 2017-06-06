import logging
import os
import subprocess
import time

logger = logging.getLogger(__name__)


class DeviceManager:
    port = "5554"
    emulator_id = "emulator-" + port
    is_running = False

    @classmethod
    def get_emulator(cls, min_sdk_version, target_sdk_version):
        api = _get_fitting_sdk_version(min_sdk_version, target_sdk_version)

        # TODO: maybe use -gpu on
        no_audio = "export QEMU_AUDIO_DRV=none && "
        emulator_type = str(api)
        other_opts = "-wipe-data -use-system-libs -writable-system -no-boot-anim -http-proxy http://0.0.0.0:8080"

        cmd = no_audio + "emulator -avd " + emulator_type + " -port " + cls.port + " " + other_opts + "  &"
        logger.debug(cmd)
        subprocess.check_call(cmd, shell=True)

        _wait_until_boot_completed(cls.emulator_id)
        cls.is_running = True

        return cls.emulator_id

    @classmethod
    def shutdown_emulator(cls):
        if cls.is_running:
            cmd = "adb -s " + cls.emulator_id + " emu kill"
            logger.debug(cmd)
            subprocess.check_call(cmd, shell=True)


def _get_fitting_sdk_version(min_sdk_version, target_sdk_version):
    available_versions = os.environ['API_VERSIONS'].split(',')
    ordered_available_versions = sorted([int(a) for a in available_versions], reverse=True)
    preferred_versions = range(int(min_sdk_version or target_sdk_version), int(target_sdk_version) + 1)

    # use highest API version in range between min and target API version
    for v in ordered_available_versions:
        if v in preferred_versions:
            return v

    # use next highest API version
    ordered_available_versions.reverse()
    for v in ordered_available_versions:
        if v > int(target_sdk_version):
            return v

    # TODO: what to do here?
    return None


def _wait_until_boot_completed(emulator_id):
    cmd = "adb -s " + emulator_id + " wait-for-device shell getprop sys.boot_completed"
    while "1" not in subprocess.check_output(cmd, shell=True):
        time.sleep(1)
        logger.debug(cmd)
