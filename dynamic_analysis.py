import device_manager
import subprocess
import time
import logging


logger = logging.getLogger(__name__)


def analyze_dynamically(apk_name, static_analysis_results):
    emulator_id = device_manager.get_emulator()
    apk_path = "input_apks/" + apk_name + ".apk"

    install_apk(emulator_id, apk_path)

    for result in static_analysis_results.result_list:
        # reset the window, press enter two times
        press_enter(emulator_id)
        press_enter(emulator_id)

        # TODO: also support services?
        if result.tag == "activity":
            start_activity(emulator_id, result.meth_nm)
            time.sleep(5)

            # TODO: get smart input
            # TODO: UI automation

    uninstall_apk(emulator_id, static_analysis_results.package)


def install_apk(emulator_id, apk_path):
    cmd = "adb -s " + emulator_id + " install " + apk_path
    logger.debug(cmd)
    subprocess.check_call(cmd, shell=True)


def press_enter(emulator_id):
    cmd = "adb -s " + emulator_id + " shell input keyevent 66"
    logger.debug(cmd)
    subprocess.check_call(cmd, shell=True)


def start_activity(emulator_id, meth_nm):
    last_dot = meth_nm.rindex('.')
    component_name = meth_nm[:last_dot] + "/" + meth_nm[last_dot:]
    cmd = "adb -s " + emulator_id + " shell am start -n " + component_name
    logger.debug(cmd)
    subprocess.check_call(cmd, shell=True)


def uninstall_apk(emulator_id, package_name):
    cmd = "adb -s " + emulator_id + " uninstall " + package_name
    logger.debug(cmd)
    subprocess.check_call(cmd, shell=True)
