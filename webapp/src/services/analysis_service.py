from common.services import templates_service
from src.app import celery, apks
from flask_login import current_user


def start_analysis(files):
    if 'apks' in files:
        filenames = []
        for file in files.getlist('apks'):
            filenames += [apks.save(file).replace('.apk', '')]

        for filename in filenames:
            celery.send_task('static_analysis_task', args=[filename, current_user.username])

        html = templates_service.render_all_scenario_settings(filenames, current_user)
        return html
    return None

