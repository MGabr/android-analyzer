import device_manager
import subprocess
import time
import logging
from com.dtmilano.android.viewclient import ViewClient
from mitm_proxy import start_mitm_proxy, kill_mitm_proxy
from network_monitor import start_network_monitor, kill_network_monitor


logger = logging.getLogger(__name__)


def analyze_dynamically(apk_name, static_analysis_results, smart_input_results):
    mitm_proxy_process = start_mitm_proxy()

    emulator_id = device_manager.get_emulator()
    apk_path = "input_apks/" + apk_name + ".apk"

    install_apk(emulator_id, apk_path)

    start_app(emulator_id, static_analysis_results.package)
    time.sleep(1)
    network_monitor_process = start_network_monitor(emulator_id, static_analysis_results.package)

    for result in static_analysis_results.result_list:
        # reset the window, press enter two times
        press_enter(emulator_id)
        press_enter(emulator_id)

        # TODO: also support services?
        if result.tag == "activity":
            start_activity(emulator_id, result.meth_nm)
            time.sleep(5)

            # TODO: get smart input

            device, serialno = ViewClient.connectToDeviceOrExit(serialno=emulator_id)
            logger.debug("Connected to device with serialno %s" % emulator_id)
            vc = ViewClient(device, serialno)
            logger.debug("Created ViewClient for serialno %s" % serialno)

            # editable = vc.findViewWithAttributeThatMatches("text:getSelectionEnd", "^((?!-).)*$")
            editTexts = vc.findViewsWithAttribute("class", "android.widget.EditText")
            logger.debug("editable %s" % str(editTexts))
            clickableViews = vc.findViewsWithAttribute("clickable", "true")
            logger.debug("clickable %s" % str(clickableViews))
            listviews = vc.findViewsWithAttribute("class", "android.widget.ListView")
            logger.debug("listview %s" % str(listviews))

            # fill all EditText with smart input
            for editText in editTexts:
                logger.debug("EditText %s" % str(editText))
                # TODO: fill in smart input
                logger.debug("edit text: %s" % editText.getText())
                editText.touch()
                editText.setText("https://www.google.at")
                logger.debug("edit text: %s" % editText.getText())

            for clickableView in clickableViews:
                logger.debug("Clickable View %s" % str(clickableView))
                oldWindow = device.getFocusedWindowName()
                clickableView.touch()
                time.sleep(5)
                newWindow = device.getFocusedWindowName()
                if newWindow != oldWindow:
                    logger.debug("Focused window changed while clicking view. Pressing back button.")
                    press_back(emulator_id)
                    time.sleep(5)
                    newWindow = device.getFocusedWindowName()
                    if newWindow != oldWindow:
                        logger.debug("Did not return to old focused window after pressing back button. Trying enter.")
                        press_enter(emulator_id)
                        press_enter(emulator_id)
                        if newWindow != oldWindow:
                            logger.debug("Did not return to old focused window after pressing enter.")
                            break
            # TODO: listviews

    kill_network_monitor(network_monitor_process)

    uninstall_apk(emulator_id, static_analysis_results.package)

    kill_mitm_proxy(mitm_proxy_process)


def install_apk(emulator_id, apk_path):
    cmd = "adb -s " + emulator_id + " install " + apk_path
    logger.debug(cmd)
    subprocess.check_call(cmd, shell=True)


def start_app(emulator_id, package_name):
    cmd = "adb -s " + emulator_id + " shell monkey -p " + package_name + " 1"
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


def press_back(emulator_id):
    cmd = "adb -s " + emulator_id + " shell input keyevent 4"
    logger.debug(cmd)
    subprocess.check_call(cmd, shell=True)
