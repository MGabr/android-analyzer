import logging

from celery import Celery

from src.dict_object import DictObject
from src.dynamic.dynamic_analysis import analyze_dynamically


logging.basicConfig(level=logging.DEBUG)


celery = Celery(broker='amqp://admin:mypass@rabbit//', backend='file:///files/tmp/celery_results')
celery.conf.update()


@celery.task(bind=True, name='dynamic_analysis_task', default_retry_delay=60, max_retries=1, soft_time_limit=600)
def dynamic_analysis_task(self, apk_name, scenarios, smart_input_results, smart_input_assignment):
    log_analysis_results = analyze_dynamically(
        apk_name,
        DictObject(scenarios),
        DictObject(smart_input_results),
        DictObject(smart_input_assignment),
        task=self)

    return {'msg_done': 'Analysed app in all scenarios.',
            'log_analysis_results': log_analysis_results,
            'state_count': len(log_analysis_results) + 1}
