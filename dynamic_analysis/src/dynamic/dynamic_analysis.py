import logging
import re
import subprocess
import time

from celery.exceptions import SoftTimeLimitExceeded
from com.dtmilano.android.viewclient import ViewClient

from common.dto.dynamic_analysis import DynamicAnalysisResult, LogAnalysisResult
from common.services import templates_service
from src.definitions import INPUT_APK_DIR
from src.environment.certificate_installation import InstalledCertificates
from src.environment.device_manager import DeviceManager
from src.environment.mitm_proxy import MitmProxy
from src.environment.network_monitor import NetworkMonitor
from src.logs.log_analysis import analyse_log, try_analyse_log


logger = logging.getLogger(__name__)


timed_out = False


def analyze_dynamically(apk_name, scenarios, smart_input_results, smart_input_assignment, socketio, current_user):
    logger.info('Setting up analysis environment.')

    emulator_id = None
    apk_path = INPUT_APK_DIR + apk_name + ".apk"
    installed = False
    failed_results = []
    global timed_out
    timed_out = False
    try:
        # ==== Setup ====
        emulator_id = DeviceManager.get_emulator(scenarios.min_sdk_version, scenarios.target_sdk_version)

        install_apk(emulator_id, apk_path)
        installed = True

        start_app(emulator_id, scenarios.package)
        # ==== ===== ====

        time.sleep(1)

        logger.info('Analysing activies of scenario.')
        run_scenarios(
            scenarios,
            smart_input_results,
            smart_input_assignment,
            emulator_id,
            socketio,
            current_user)

    except SoftTimeLimitExceeded:
        logger.exception("Timed out")
        failed_results = [LogAnalysisResult(DynamicAnalysisResult(s, timed_out=True)) for s in scenarios.scenario_list]
        timed_out = True
    except Exception:
        logger.exception("Crash during setup")
        failed_results = [LogAnalysisResult(DynamicAnalysisResult(s, crashed_on_setup=True))
                          for s in scenarios.scenario_list]
    finally:
        # ==== Shutdown ====
        if installed:
            uninstall_apk(emulator_id, scenarios.package)

        DeviceManager.shutdown_emulator()

        time.sleep(5) # wait for emulator to be shut down
        # ==== ======== ====

    if failed_results:
        html = templates_service.render_log_analysis_results(failed_results)
        socketio.emit('html', {'html': html}, room=current_user.username)

    return timed_out


def run_scenarios(scenarios, smart_input_results, smart_input_assignment, emulator_id, socketio, current_user):
    global timed_out
    log_id = 0
    for index, scenario in enumerate(scenarios.scenario_list):

        logger.info('Analysing activity ' + scenario.static_analysis_result.activity_name)
        log_id += 1
        log_analysis_result = run_scenario(
            scenario,
            scenarios,
            log_id,
            emulator_id,
            smart_input_results,
            smart_input_assignment)

        html = templates_service.render_log_analysis_results([log_analysis_result])
        socketio.emit('html', {'html': html}, room=current_user.username)

        if timed_out:
            remaining_scenarios = scenarios.scenario_list[index+1:]
            failed_results = [LogAnalysisResult(DynamicAnalysisResult(s, timed_out=True)) for s in remaining_scenarios]
            if failed_results:
                html = templates_service.render_log_analysis_results(failed_results)
                socketio.emit('html', {'html': html}, room=current_user.username)


def run_scenario(scenario, scenarios, log_id, emulator_id, smart_input_results, smart_input_assignment):
    global timed_out
    try:
        with InstalledCertificates(emulator_id, scenario.scenario_settings.sys_certificates):

            with MitmProxy(
                    scenario.scenario_settings.mitm_certificate,
                    scenario.scenario_settings.add_upstream_certs,
                    log_id):

                with NetworkMonitor(scenario.scenario_settings.strace, emulator_id, scenarios.package, log_id):

                    run_ui_traversal(scenario, emulator_id, smart_input_results, smart_input_assignment)

                    # wait before shutting down mitmproxy since there might be a last request caused by ui traversal
                    time.sleep(5)

                    return analyse_log(DynamicAnalysisResult(scenario, log_id))
    except SoftTimeLimitExceeded:
        logger.exception("Timed out")
        timed_out = True
        return try_analyse_log(DynamicAnalysisResult(scenario, log_id, timed_out=True))
    except Exception:
        logger.exception("Crash during running scenario")
        return analyse_log(DynamicAnalysisResult(scenario, log_id, crashed_on_run=True))


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

