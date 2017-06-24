import logging
from urllib import urlretrieve

from celery import Celery
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
from src.static.static_analysis import StaticAnalyzer, StaticAnalysisResults


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


celery = Celery(broker=config.RABBITMQ_URL)
celery.conf.update({
    'CELERY_ROUTES': {'dynamic_analysis_task': {'queue': 'dynamic_queue'}},
    'CELERYD_PREFETCH_MULTIPLIER': 1
})


socketio = SocketIO(message_queue=config.RABBITMQ_URL, async_mode='threading')


@celery.task(name='static_analysis_task', base=SQLAlchemyTask)
def static_analysis_task(apk_name, username):
    try:
        logger.info("Retrieving APK.")
        urlretrieve(config.WEBAPP_URL + '/apk/' + apk_name, INPUT_APK_DIR + apk_name + ".apk")

        logger.info('Disassembling APK.')
        disassembled_path = disassemble_apk(apk_name)

        logger.info('Disassembled APK. Now statically analysing app.')
        apk_analysis = ApkAnalysis(apk_name)
        methods_w_http = apk_analysis.get_methods_with_http()
        static_analysis_results = StaticAnalyzer().analyze_statically(disassembled_path, apk_name, methods_w_http)
        activities = apk_analysis.get_all_activities_results()

        static_analysis_results = StaticAnalysisResults(
            static_analysis_results.apk_filename,
            static_analysis_results.package,
            static_analysis_results.min_sdk_version,
            static_analysis_results.target_sdk_version,
            static_analysis_results.result_list + activities)

        logger.info('Analysed app statically, now sending html to socket')
        current_user = Session.query(User).filter(User.username == username).one()
        html = templates_service.render_static_analysis_results(static_analysis_results, current_user)
        socketio.emit('html', {'html': html}, room=username)

        logger.info('Sent html to socket. Now generating smart input for app.')
        smart_input_results = apk_analysis.get_smart_input()

        logger.info('Generated smart input for app. Now getting scenarios for dynamic analysis.')
        scenario_datas = scenario_service.get_all_of_user(static_analysis_results, current_user)

        if scenario_service.has_activities_to_select(static_analysis_results, current_user):
            logger.info("Saving static analysis and smart input results for activity selection later.")
            Session.add(static_analysis_results)
            smart_input_results_json = {clazz: [tf.__json__() for tf in tfs]
                                        for clazz, tfs in smart_input_results.iteritems()}
            smart_input_results_db = SmartInputResult(apk_filename=apk_name, result=smart_input_results_json)
            Session.add(smart_input_results_db)
            Session.commit()

        if scenario_datas:
            logger.info('Starting dynamic analysis tasks.')
            for scenario_data in scenario_datas:
                celery.send_task('dynamic_analysis_task', args=[
                    static_analysis_results.apk_filename,
                    scenario_data,
                    smart_input_results,
                    username])
        else:
            logger.info('No scenarios for dynamic analysis.')

    except Exception as e:
        logger.exception("Static analysis crashed")
