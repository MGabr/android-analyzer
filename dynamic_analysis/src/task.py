import logging

from celery import Celery

from src.dict_object import DictObject
from src.dynamic.dynamic_analysis import analyze_dynamically
from src.logs.log_analysis import analyse_logs


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


celery = Celery(broker='amqp://admin:mypass@rabbit//', backend='rpc://')
celery.conf.update()


@celery.task(bind=True, name='dynamic_analysis_task')
def dynamic_analysis_task(self, apk_name, scenarios, smart_input_results, smart_input_assignment):
    dynamic_analysis_results = analyze_dynamically(
        apk_name,
        DictObject(scenarios),
        DictObject(smart_input_results),
        DictObject(smart_input_assignment),
        task=self)
    log_analysis_results = analyse_logs(dynamic_analysis_results)

    return {'msg_done': 'Analysed app in all scenarios.', 'log_analysis_results': log_analysis_results}
