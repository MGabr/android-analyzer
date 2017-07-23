import logging
import os
from urllib import urlretrieve

from celery import Celery
from celery.exceptions import WorkerTerminate
from flask_socketio import SocketIO

from common import config
# Imports needed for SQLAlchemy to work
from common.models import certificate, scenario_settings, sys_certificates_table, user, user_certificates_table
from common.models.user import User
from common.models.smart_input import SmartInputResult
from common.services import templates_service, scenario_service
from src.db_base import SQLAlchemyTask, Session
from src.definitions import INPUT_APK_DIR
from src.static.apk_analysis import ApkAnalysis
from src.static.apk_disassembly import disassemble_apk
from src.static.static_analysis import StaticAnalyzer, StaticAnalysisResults, requires_internet_permission


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


celery = Celery(broker=config.RABBITMQ_URL)
celery.conf.update({
    'CELERY_ROUTES': {'dynamic_analysis_task': {'queue': 'dynamic_queue'}},
    'CELERYD_PREFETCH_MULTIPLIER': 1,
    'CELERY_ACKS_LATE': True
})


socketio = SocketIO(message_queue=config.RABBITMQ_URL, async_mode='threading')


@celery.task(
    name='static_analysis_task',
    base=SQLAlchemyTask,
    acks_late=True)
def static_analysis_task(apk_name, username):
    try:
        logger.info("Retrieving APK.")
        urlretrieve(config.WEBAPP_URL + '/apk/' + apk_name, INPUT_APK_DIR + apk_name + ".apk")

        logger.info('Disassembling APK.')
        crashed_on_disass = False
        try:
            disassembled_path = disassemble_apk(apk_name)
        except:
            crashed_on_disass = True
            static_analysis_results = StaticAnalysisResults(apk_name, None, None, None, [])

        internet_perm = True
        if not crashed_on_disass:
            logger.info('Disassembled APK. Now statically analysing app.')
            package, internet_perm = requires_internet_permission(disassembled_path)
            if internet_perm:
                static_analysis_results = StaticAnalyzer().analyze_statically(disassembled_path, apk_name)
                apk_analysis = ApkAnalysis(apk_name)
                activities = apk_analysis.get_all_activities_results()

                static_analysis_results = as_combined_static_analysis_results(
                    static_analysis_results,
                    static_analysis_results.result_list + activities)
            else:
                static_analysis_results = StaticAnalysisResults(apk_name, package, None, None, [])

        logger.info('Analysed app statically, now getting scenarios for dynamic analysis and sending html.')
        current_user = Session.query(User).filter(User.username == username).one()
        html = templates_service.render_static_analysis_results(
            static_analysis_results,
            current_user,
            crashed_on_disass=crashed_on_disass,
            internet_perm=internet_perm)
        send_html(html, username)

        if crashed_on_disass:
            logger.error("Static analysis crashed during disassembly of APK. No further analysis")
            return

        if not internet_perm:
            logger.info("App does not request internet permission. No further static dynamic analysis")
            return

        scenario_datas = scenario_service.get_all_of_user(static_analysis_results, current_user)
        if not scenario_datas:
            logger.info('No scenarios for dynamic analysis.')
            return

        html = templates_service.render_scenario_datas(scenario_datas)
        send_html(html, username)

        logger.info('Sent html to socket. Now generating smart input for app.')
        smart_input_results = apk_analysis.get_smart_input()
        logger.info('Generated smart input for app.')

        if scenario_service.has_activities_to_select(static_analysis_results, current_user):
            logger.info("Saving static analysis and smart input results for activity selection later.")
            Session.add(static_analysis_results)
            smart_input_results_json = {clazz: [tf.__json__() for tf in tfs]
                                        for clazz, tfs in smart_input_results.iteritems()}
            smart_input_results_db = SmartInputResult(apk_filename=apk_name, result=smart_input_results_json)
            Session.add(smart_input_results_db)
            Session.commit()

        logger.info('Starting dynamic analysis tasks.')
        for scenario_data in scenario_datas:
            try:
                if not scenario_data.is_selected_activities():
                    celery.send_task('dynamic_analysis_task', args=[
                        static_analysis_results.apk_filename,
                        scenario_data,
                        smart_input_results,
                        username])
            except Exception:
                logger.exception("Can't send dynamic analysis tasks")
                raise WorkerTerminate()

    except WorkerTerminate as e:
        raise e
    except Exception as e:
        logger.exception("Static analysis crashed")
        if not 'current_user' in locals():
            current_user = Session.query(User).filter(User.username == username).one()
        if not 'static_analysis_results' in locals():
            static_analysis_results = StaticAnalysisResults(apk_name, None, None, None, [])
        html = templates_service.render_static_analysis_results(static_analysis_results, current_user, crashed=True)
        send_html(html, username)
    finally:
        if os.path.isfile(INPUT_APK_DIR + apk_name + ".apk"):
            os.remove(INPUT_APK_DIR + apk_name + ".apk")


def as_combined_static_analysis_results(r, combined_result_list):
    return StaticAnalysisResults(
        r.apk_filename,
        r.package,
        r.min_sdk_version,
        r.target_sdk_version,
        combined_result_list)


def send_html(html, username):
    try:
        socketio.emit('html', {'html': html}, room=username)
    except Exception:
        logger.exception("Can't send html")
        raise WorkerTerminate()
