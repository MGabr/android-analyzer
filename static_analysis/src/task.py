import logging
from urllib import urlretrieve

from celery import Celery
from flask_socketio import SocketIO

# Imports needed for SQLAlchemy to work
from common.models import certificate, scenario_settings, sys_certificates_table, user, user_certificates_table
from common.models.user import User
from common.services import templates_service
from src.db_base import SQLAlchemyTask, Session
from src.definitions import INPUT_APK_DIR
from src.services import scenario_service
from src.static.apk_analysis import ApkAnalysis
from src.static.apk_disassembly import disassemble_apk
from src.static.static_analysis import StaticAnalyzer, StaticAnalysisResults


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


celery = Celery(broker='amqp://admin:mypass@rabbit//')
celery.conf.update({
    'CELERY_ROUTES': {'dynamic_analysis_task': {'queue': 'dynamic_queue'}},
    'CELERYD_PREFETCH_MULTIPLIER': 1
})


socketio = SocketIO(message_queue='amqp://admin:mypass@rabbit//', async_mode='threading')


@celery.task(name='static_analysis_task', base=SQLAlchemyTask)
def static_analysis_task(apk_name, username):
    try:
        logger.info("Retrieving APK.")
        urlretrieve('http://webapp:5000/apk/' + apk_name, INPUT_APK_DIR + apk_name + ".apk")

        logger.info('Disassembling APK.')
        disassembled_path = disassemble_apk(apk_name)

        logger.info('Disassembled APK. Now statically analysing app.')
        apk_analysis = ApkAnalysis(apk_name)
        methods_w_https = apk_analysis.get_methods_with_https()
        static_analysis_results = StaticAnalyzer().analyze_statically(disassembled_path, apk_name, methods_w_https)
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
