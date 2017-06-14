import logging
import re
import subprocess
import time

from com.dtmilano.android.viewclient import ViewClient

from src.definitions import INPUT_APK_DIR, LOGS_DIR
from src.environment.certificate_installation import install_as_system_certificate, uninstall_system_certificate
from src.environment.device_manager import DeviceManager
from src.environment.mitm_proxy import start_mitm_proxy, kill_mitm_proxy
from src.environment.network_monitor import start_network_monitor, kill_network_monitor
from src.logs.log_analysis import analyse_logs, LogAnalysisResult
from celery.exceptions import SoftTimeLimitExceeded


logger = logging.getLogger(__name__)


class DynamicAnalysisResult:
    # if no dynamic analysis was run, log_id should not be set
    def __init__(self,
                 scenario,
                 log_id=None,
                 crashed_on_run=False,
                 crashed_on_setup=False,
                 is_running=False,
                 timed_out=False):
        self.scenario = scenario
        self.log_id = log_id
        self.crashed_on_run = crashed_on_run
        self.crashed_on_setup = crashed_on_setup
        self.is_running = is_running
        self.timed_out = timed_out

        self.has_been_run = bool(self.log_id)

    def get_mitm_proxy_log(self):
        return LOGS_DIR + "mitm_proxy_log" + str(self.log_id)

    def get_network_monitor_log(self):
        return LOGS_DIR + "network_monitor_log" + str(self.log_id)

    def __json__(self):
        return {
            'scenario': self.scenario,
            'log_id': self.log_id,
            'crashed_on_run': self.crashed_on_run,
            'crashed_on_setup': self.crashed_on_setup,
            'has_been_run': self.has_been_run,
            'is_running': self.is_running,
            'timed_out': self.timed_out}


def analyze_dynamically(apk_name, scenarios, smart_input_results, smart_input_assignment, task=None):
    set_task_progress__setup(task, scenarios)

    emulator_id = None
    apk_path = INPUT_APK_DIR + apk_name + ".apk"
    installed = False
    try:
        # ==== Setup ====
        emulator_id = DeviceManager.get_emulator(scenarios.min_sdk_version, scenarios.target_sdk_version)

        install_apk(emulator_id, apk_path)
        installed = True

        start_app(emulator_id, scenarios.package)
        # ==== ===== ====

        time.sleep(1)

        log_analysis_results = run_scenarios(
            scenarios,
            smart_input_results,
            smart_input_assignment,
            emulator_id,
            task)
    except SoftTimeLimitExceeded:
        logger.exception("Timed out")
        log_analysis_results = analyse_logs([DynamicAnalysisResult(s, timed_out=True)
                                             for s in scenarios.scenario_list])
    except Exception:
        logger.exception("Crash during setup")
        log_analysis_results = analyse_logs([DynamicAnalysisResult(s, crashed_on_setup=True)
                                             for s in scenarios.scenario_list])
    finally:
        # ==== Shutdown ====
        if installed:
            uninstall_apk(emulator_id, scenarios.package)

        DeviceManager.shutdown_emulator()

        time.sleep(5) # wait for emulator to be shut down
        # ==== ======== ====

    return log_analysis_results


def set_task_progress__setup(task, scenarios):
    if task:
        current_log_analysis_results = [LogAnalysisResult(DynamicAnalysisResult(s, is_running=True))
                                        for s in scenarios.scenario_list]
        task.update_state(
            state='PROGRESS',
            meta={'msg_done': 'Started dynamic analysis.',
                  'msg_currently': 'Now setting up dynamic analysis environment.',
                  'log_analysis_results': current_log_analysis_results,
                  'state_count': 0})


def set_task_progress__scenarios(task, last_scenario, scenario, scenarios, finished_log_analysis_results):
    if task:
        if last_scenario:
            msg_done = 'Analysed activity ' + last_scenario.static_analysis_result.activity_name + '.'
        else:
            msg_done = 'Set up dynamic analysis environment.'

        msg_currently = 'Analysing activity ' + scenario.static_analysis_result.activity_name + '.'

        i = scenarios.scenario_list.index(scenario)
        remaining_scenarios = scenarios.scenario_list[i:]
        current_log_analysis_results = [LogAnalysisResult(DynamicAnalysisResult(s, is_running=True))
                                        for s in remaining_scenarios]
        current_log_analysis_results += finished_log_analysis_results

        task.update_state(
            state='PROGRESS',
            meta={'msg_done': msg_done,
                  'msg_currently': msg_currently,
                  'log_analysis_results': current_log_analysis_results,
                  'state_count': i + 1})


def run_scenarios(scenarios, smart_input_results, smart_input_assignment, emulator_id, task):
    log_id = 0
    last_scenario = None
    log_analysis_results = []
    for scenario in scenarios.scenario_list:
        set_task_progress__scenarios(task, last_scenario, scenario, scenarios, log_analysis_results)

        log_id += 1
        log_analysis_results += run_scenario(
            scenario,
            scenarios,
            log_id,
            emulator_id,
            smart_input_results,
            smart_input_assignment)
        last_scenario = scenario

    return log_analysis_results


def run_scenario(scenario, scenarios, log_id, emulator_id, smart_input_results, smart_input_assignment):
    installed_certificate_names = list()
    mitm_proxy_process = None
    network_monitor_process = None
    try:
        # ==== Setup ====
        if scenario.scenario_settings.sys_certificates:
            for sys_certificate in scenario.scenario_settings.sys_certificates:
                installed_certificate_names += [install_as_system_certificate(emulator_id, sys_certificate)]

        mitm_proxy_process = start_mitm_proxy(
            scenario.scenario_settings.mitm_certificate,
            scenario.scenario_settings.add_upstream_certs,
            log_id)

        if scenario.scenario_settings.strace:
            network_monitor_process = start_network_monitor(emulator_id, scenarios.package, log_id)
        # ==== ===== ====

        run_ui_traversal(scenario, emulator_id, smart_input_results, smart_input_assignment)

        time.sleep(5)  # wait before shutting down mitmproxy since there might be a last request caused by ui traversal

        return analyse_logs([DynamicAnalysisResult(scenario, log_id)])
    except SoftTimeLimitExceeded:
        logger.exception("Timed out")
        return analyse_logs([DynamicAnalysisResult(scenario, log_id, timed_out=True)])
    except Exception:
        logger.exception("Crash during running scenario")
        return analyse_logs([DynamicAnalysisResult(scenario, log_id, crashed_on_run=True)])
    finally:
        # ==== Shutdown ====
        for name in installed_certificate_names:
            uninstall_system_certificate(emulator_id, name)

        if network_monitor_process:
            kill_network_monitor(network_monitor_process)
        if mitm_proxy_process:
            kill_mitm_proxy(mitm_proxy_process)
        # ==== ======== ====


def run_ui_traversal(scenario, emulator_id, smart_input_results, smart_input_assignment):
    smart_input_for_activity = smart_input_results.get(scenario.static_analysis_result.activity_name)

    # reset the window, press enter two times
    press_enter(emulator_id)
    press_enter(emulator_id)

    start_activity(emulator_id, scenario.static_analysis_result.activity_name)

    device, serialno = ViewClient.connectToDeviceOrExit(serialno=emulator_id)
    vc = ViewClient(device, serialno, autodump=False)

    # try dumping 5 times, before timing out
    dump_tries = 0
    dump_error = True
    while dump_error and dump_tries < 5:
        dump_error = False
        dump_tries += 1
        try:
            vc.dump(sleep=5)
        except Exception:
            dump_error = True
    if dump_error:
        raise SoftTimeLimitExceeded()

    edittexts = vc.findViewsWithAttribute("class", "android.widget.EditText")
    logger.info("EditText views: %s" % str(edittexts))
    clickable_views = vc.findViewsWithAttribute("clickable", "true")
    logger.info("Clickable views: %s" % str(clickable_views))
    listviews = vc.findViewsWithAttribute("class", "android.widget.ListView")
    logger.info("ListViews: %s" % str(listviews))

    fill_edit_texts(edittexts, smart_input_for_activity, smart_input_assignment, vc, emulator_id)

    click_clickable_views(clickable_views, vc, device, emulator_id)

    # TODO: listviews


def fill_edit_texts(edittexts, smart_input_for_activity, smart_input_assignment, vc, emulator_id):
    for edittext in edittexts:
        fill_edit_text(edittext, smart_input_for_activity, smart_input_assignment, vc, emulator_id)


def fill_edit_text(edittext, smart_input_for_activity, smart_input_assignment, vc, emulator_id):
    smart_input = get_smart_input_for_edittext(
        edittext.getId(),
        smart_input_for_activity,
        smart_input_assignment)
    logger.info("Smart input for EditText: " + smart_input + ", " + repr(edittext))
    edittext.touch()
    edittext.setText(smart_input)
    if vc.isKeyboardShown():
        press_back(emulator_id)


def click_clickable_views(clickable_views, vc, device, emulator_id):
    clickable_views_wo_edittexts = [c for c in clickable_views if c.getClass() != 'android.widget.EditText']
    for clickable_view in clickable_views_wo_edittexts:
        old_window = device.getFocusedWindowName()

        logger.info("Clicking on view: " + repr(clickable_view))
        clickable_view.touch()

        time.sleep(2)

        if vc.isKeyboardShown():
            press_back(emulator_id)

        new_window = device.getFocusedWindowName()
        if new_window != old_window:
            logger.warn("Focused window changed while clicking view. Pressing back button.")
            press_back(emulator_id)

            time.sleep(5)

            new_window = device.getFocusedWindowName()
            if new_window != old_window:
                logger.warn("Did not return to old focused window after pressing back button. Trying enter.")
                press_enter(emulator_id)
                press_enter(emulator_id)
                if new_window != old_window:
                    logger.warn("Did not return to old focused window after pressing enter.")
                    break


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


def start_activity(emulator_id, activity_name):
    last_dot = activity_name.rindex('.')
    component_name = activity_name[:last_dot] + "/" + activity_name[last_dot:]
    cmd = "adb -s " + emulator_id + " shell am start -W -n " + component_name
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
            if text_field.type_class:
                if text_field.type_variation:
                    return smart_input_ass.type_variation_ass[text_field.type_variation]
                else:
                    return smart_input_ass.type_class_ass[text_field.type_class]
    return None  # TODO: what to do here?

