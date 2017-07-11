from flask_login import current_user

from common.services import templates_service, scenario_service
from common.models.smart_input import SmartInputResult
from common.models.static_analysis import StaticAnalysisResults
from src.app import celery, apks, socketio


import logging

logger = logging.getLogger(__name__)


def start_analysis(files):
    if 'apks' in files:
        filenames = []
        for file in files.getlist('apks'):
            file.filename = file.filename.replace('.', '_')[:-len('_apk')] + '.apk'
            filenames += [apks.save(file, name=file.filename).replace('.apk', '')]

        for filename in filenames:
            celery.send_task('static_analysis_task', args=[filename, current_user.username], task_id=filename)

        html = templates_service.render_all_scenario_settings(filenames, current_user)
        return html
    return None


def start_activities_analysis(filename, activities, scenario_settings_id):
    static_analysis_results = StaticAnalysisResults.query.get(filename)
    smart_input_results = SmartInputResult.query.get(filename)
    if smart_input_results:
        smart_input_results = smart_input_results.result

        scenario_datas = scenario_service.get_for_choosen_activities_and_settings(
            static_analysis_results,
            activities,
            scenario_settings_id,
            current_user)
        if scenario_datas:

            scenario_data = scenario_datas[0]

            celery.send_task('dynamic_analysis_task', args=[
                static_analysis_results.apk_filename,
                scenario_data,
                smart_input_results,
                current_user.username], task_id=current_user.username)

            html = templates_service.render_selected_activities(scenario_data, scenario_settings_id, current_user)
            socketio.emit('html', {'html': html}, room=current_user.username)
