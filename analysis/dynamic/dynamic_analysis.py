from analysis.environment import device_manager
import subprocess
import time
import logging
import re
from com.dtmilano.android.viewclient import ViewClient
from mitm_proxy import start_mitm_proxy, kill_mitm_proxy
from network_monitor import start_network_monitor, kill_network_monitor
from models.smart_input_assignments import SmartInputAssignment
from models.default_settings import default_settings
from certificate_installation import install_as_system_certificate


logger = logging.getLogger(__name__)


class DynamicAnalysisResult:
    def __init__(self, scenario, log_id):
        self.scenario = scenario
        self.log_id = log_id

    def get_mitm_proxy_log(self):
        return "logs/mitm_proxy_log" + str(self.log_id)

    def get_network_monitor_log(self):
        return "logs/network_monitor_log" + str(self.log_id)


def analyze_dynamically(apk_name, static_analysis_results, smart_input_results):
    dynamic_analysis_results = []

    emulator_id = device_manager.get_emulator()
    apk_path = "input_apks/" + apk_name + ".apk"

    install_apk(emulator_id, apk_path)

    start_app(emulator_id, static_analysis_results.package)
    time.sleep(1)

    smart_input_assignment = SmartInputAssignment()

    log_id = 0
    for scenario in default_settings.get_scenarios(static_analysis_results):
        logger.debug("Checking for vulnerable " + " and ".join(scenario.scenario_settings.vuln_types) + " implementations")

        log_id += 1
        mitm_proxy_process = start_mitm_proxy(scenario.scenario_settings.mitm_certificate, log_id)
        network_monitor_process = start_network_monitor(emulator_id, static_analysis_results.package, log_id)

        if scenario.scenario_settings.sys_certificates:
            for sys_certificate in scenario.scenario_settings.sys_certificates:
                install_as_system_certificate(emulator_id, sys_certificate)

        # reset the window, press enter two times
        press_enter(emulator_id)
        press_enter(emulator_id)

        smart_input_for_activity = smart_input_results[scenario.activity_name]

        # TODO: also support services?
        start_activity(emulator_id, scenario.activity_name)
        time.sleep(5)

        device, serialno = ViewClient.connectToDeviceOrExit(serialno=emulator_id)
        logger.debug("Connected to device with serialno %s" % emulator_id)
        vc = ViewClient(device, serialno)
        logger.debug("Created ViewClient for serialno %s" % serialno)

        editTexts = vc.findViewsWithAttribute("class", "android.widget.EditText")
        logger.debug("editable %s" % str(editTexts))
        clickableViews = vc.findViewsWithAttribute("clickable", "true")
        logger.debug("clickable %s" % str(clickableViews))
        listviews = vc.findViewsWithAttribute("class", "android.widget.ListView")
        logger.debug("listview %s" % str(listviews))

        # fill all EditText with smart input
        for editText in editTexts:
            smart_input = get_smart_input_for_edittext(
                editText.getId(),
                smart_input_for_activity,
                smart_input_assignment)
            logger.debug("smart_input: " + str(smart_input))
            editText.touch()
            editText.setText(smart_input)
            logger.debug("edit text: %s" % editText.getText())
            if vc.isKeyboardShown():
                press_back(emulator_id)

        for clickableView in clickableViews:
            oldWindow = device.getFocusedWindowName()
            clickableView.touch()
            time.sleep(2)
            if vc.isKeyboardShown():
                press_back(emulator_id)
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
        kill_mitm_proxy(mitm_proxy_process)

        dynamic_analysis_results += [DynamicAnalysisResult(scenario, log_id)]

    uninstall_apk(emulator_id, static_analysis_results.package)

    return dynamic_analysis_results


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


def get_smart_input_for_edittext(edittext_id, smart_input_for_activity, smart_input_ass):
    edittext_name = re.match(".*id/(.*)$", edittext_id).group(1)

    for text_field in smart_input_for_activity:
        if text_field.name == edittext_name:
            type_class = text_field.get_type_class()
            if type_class:
                type_variation = text_field.get_type_variation(type_class)
                if type_variation:
                    return smart_input_ass.type_variation_ass[type_variation]
                else:
                    return smart_input_ass.type_class_ass[text_field.get_type_class()]
    return None  # TODO: what to do here?

