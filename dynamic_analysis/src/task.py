import logging
from urllib import urlretrieve

from celery import Celery
from flask_socketio import SocketIO

from common import config
from common.dto.scenario import ScenariosData
from common.dto_dependency_loader import DtoDependencyLoader
# Imports needed for SQLAlchemy to work
from common.models import certificate, scenario_settings, sys_certificates_table, user, user_certificates_table, static_analysis
from common.models.smart_input import SmartInputAssignment
from common.models.user import User
from src.db_base import Session, SQLAlchemyTask
from src.definitions import INPUT_APK_DIR
from src.dict_object import DictObject
from src.dynamic.dynamic_analysis import analyze_dynamically


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


celery = Celery(broker=config.RABBITMQ_URL)


socketio = SocketIO(message_queue=config.RABBITMQ_URL, async_mode='threading')


@celery.task(
    name='dynamic_analysis_task',
    default_retry_delay=10,
    max_retries=1,
    soft_time_limit=600,
    base=SQLAlchemyTask)
def dynamic_analysis_task(apk_name, scenarios, smart_input_results, username):
    try:
        logger.info('Retrieving APK and loading DTO dependencies.')
        urlretrieve(config.WEBAPP_URL + '/apk/' + apk_name, INPUT_APK_DIR + apk_name + ".apk")
        DtoDependencyLoader.session = Session
        scenarios = ScenariosData(**scenarios)

        current_user = Session.query(User).filter(User.username == username).one()

        logger.info('Starting dynamic analysis.')
        timed_out = analyze_dynamically(
            apk_name,
            scenarios,
            DictObject(smart_input_results),
            SmartInputAssignment(),
            socketio,
            current_user)

        if timed_out:
            dynamic_analysis_task.retry()

    except Exception:
        logger.exception("Dynamic analysis crashed")
