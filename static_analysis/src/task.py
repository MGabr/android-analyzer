import logging

from celery import Celery, states

from src.static.apk_activities import GetApkActivities
from src.static.apk_disassembly import disassemble_apk
from src.static.smart_input import generate_smart_input
from src.static.static_analysis import StaticAnalyzer, StaticAnalysisResults

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


celery = Celery(broker='amqp://admin:mypass@rabbit//', backend='file:///files/tmp/celery_results')
celery.conf.update()


@celery.task(bind=True, name='static_analysis_task')
def static_analysis_task(self, apk_name):
    try:
        self.update_state(state='PROGRESS', meta={'msg_currently': 'Disassembling APK.'})

        disassembled_path = disassemble_apk(apk_name)

        self.update_state(
            state='PROGRESS',
            meta={'msg_done': 'Disassembled APK.', 'msg_currently': 'Now statically analysing app.'})

        static_analysis_results = StaticAnalyzer().analyze_statically(disassembled_path, apk_name)

        activities = GetApkActivities(apk_name).get_all_activities()

        static_analysis_results = StaticAnalysisResults(
            static_analysis_results.apk_filename,
            static_analysis_results.package,
            static_analysis_results.min_sdk_version,
            static_analysis_results.target_sdk_version,
            static_analysis_results.result_list + activities)

        self.update_state(
            state='PROGRESS',
            meta={'msg_done': 'Analysed app statically.',
                  'msg_currently': 'Now generating smart input for app.',
                  'static_analysis_results': static_analysis_results})

        smart_input_results = generate_smart_input(apk_name)

        return {'msg_done': 'Generated smart input for app.',
                'static_analysis_results': static_analysis_results,
                'smart_input_results': smart_input_results}
    except Exception as e:
        self.update_state(state=states.FAILURE, meta={'msg_done': 'Static analysis crashed!'})
