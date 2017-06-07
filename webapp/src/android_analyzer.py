import logging
import os
from celery import states
from urlparse import urlparse, urljoin

from flask import request, render_template, url_for, jsonify
from flask_login import login_required

from src.app import app, apks, login_manager, make_celery
from src.context_processors import context_processor
from src.create_db import create_db, fill_db, drop_db
from src.dict_object import DictObject
from src.models.certificate import Certificate
from src.models.scenario_settings import ScenarioSettings
from src.models.smart_input_assignments import SmartInputAssignment
from src.models.vuln_type import VulnType
from src.services import certificate_service
from src.services import result_view_service
from src.services import scenario_service
from src.services import scenario_settings_service
from src.services import user_service
from src.services.errors import FormError, LoginError, FieldExistsError, EntityNotExistsError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


login_manager.login_view = "show_login"


@login_manager.user_loader
def user_loader(user_id):
    return user_service.user_loader(user_id)


celery = make_celery(app)


app.context_processor(context_processor)


# ---- Views ----

@app.route('/index', methods=['GET'])
def show_index():
    return render_template('index.html')


# same page as register
@app.route('/login', methods=['GET'])
def show_login():
    return render_template('login.html')


@login_required
@app.route('/settings', methods=['GET'])
def show_settings():
    return render_template('settings.html',
                           scenarios=scenario_settings_service.get_all_of_user(),
                           certificates=certificate_service.get_all_of_user())


@app.route('/scenario/<id>', methods=['GET'])
def show_scenario(id):
    new = id == 'new'
    sc = ScenarioSettings() if new else scenario_settings_service.get_of_user(id)
    return render_template('scenario.html',
                           new=new,
                           sc=sc,
                           vuln_types=[v for v in VulnType],
                           certs=certificate_service.get_all_of_user())


@app.route('/certificate/<id>', methods=['GET'])
def show_certificate(id):
    new = id == 'new'
    c = Certificate() if new else certificate_service.get_of_user(id)
    return render_template('certificate.html', new=new, c=c)


# ---- Api for AJAX calls ----


@app.route('/static_analysis', methods=['POST'])
def start_static_analysis():
    if 'apks' in request.files:
        filenames = []
        for file in request.files.getlist('apks'):
            filenames += [apks.save(file).replace('.apk', '')]

        tasks = []
        for filename in filenames:
            tasks += [celery.send_task('static_analysis_task', args=[filename])]

        html = result_view_service.render_all_scenario_settings(filenames)

        return _json_poll_redirects([url_for('get_static_analysis', id=task.id) for task in tasks], html=html)
    else:
        return jsonify({'error': True})


@app.route('/static_analysis/<id>', methods=['GET'])
def get_static_analysis(id):
    task = celery.AsyncResult(id)

    result = dict()

    if task.state == states.SUCCESS:
        result['dynamic_analysis_url'] = url_for('start_dynamic_analysis', static_analysis_id=task.id)
        result['activities_dynamic_analysis_url'] = url_for(
            'start_activities_dynamic_analysis',
            scenario_settings_id='replace',
            static_analysis_id=task.id)
        r = DictObject(task.result)
        result['html'] = result_view_service.render_static_analysis_results(r.static_analysis_results)

    if task.state == states.FAILURE:
        result['error'] = True

    return jsonify(result)


@app.route('/dynamic_analysis', methods=['POST'])
def start_dynamic_analysis():
    id = request.args.get('static_analysis_id')
    task = celery.AsyncResult(id)
    r = DictObject(task.result)

    # TODO: parallelize
    scenarios = scenario_service.get_all_of_user(r.static_analysis_results)

    if not scenarios.scenarios:
        # no dynamic analysis to execute, maybe only SelectedActivities?
        return jsonify({})

    apk_name = scenarios.scenarios[0].static_analysis_results.result_list[0].apk_folder.split("/")[-1]

    newtask = celery.send_task(
        'dynamic_analysis_task',
        args=[apk_name, scenarios, r.smart_input_results, SmartInputAssignment()])

    return _json_poll_redirect(url_for('get_dynamic_analysis', id=newtask.id))


@app.route('/dynamic_analysis/scenario/<scenario_settings_id>/activities', methods=['POST'])
def start_activities_dynamic_analysis(scenario_settings_id):
    id = request.args.get('static_analysis_id')
    task = celery.AsyncResult(id)
    r = DictObject(task.result)

    choosen_activities = request.get_json()
    if not choosen_activities:
        return jsonify({})

    scenarios = scenario_service.get_for_choosen_activities_and_settings(
        r.static_analysis_results,
        choosen_activities,
        scenario_settings_id)

    apk_name = scenarios.scenarios[0].static_analysis_results.result_list[0].apk_folder.split("/")[-1]

    newtask = celery.send_task(
        'dynamic_analysis_task',
        args=[apk_name, scenarios, r.smart_input_results, SmartInputAssignment()])

    html = result_view_service.render_selected_activities(scenarios, scenario_settings_id)
    return _json_poll_redirect(url_for('get_dynamic_analysis', id=newtask.id), html=html)


@app.route('/dynamic_analysis/<id>', methods=['GET'])
def get_dynamic_analysis(id):
    task = celery.AsyncResult(id)

    r = DictObject(task.result)
    if not r.get('log_analysis_results'):
        return jsonify({})

    task.forget()

    result = dict()
    result['html'] = result_view_service.render_log_analysis_results(r.log_analysis_results)
    if task.state == states.SUCCESS:
        result['finished'] = True

    return jsonify(result)

    # if task.state == 'SUCCESS':
        # r = DictObject(task.result)
        # apk_folder = r.log_analysis_results[0].dynamic_analysis_result.scenario.static_analysis_results.result_list[0].apk_folder
        # apk_name = apk_folder.split("/")[-1]

        # try:
        #     os.remove(os.path.join(app.config['UPLOADED_APKS_DEST'], apk_name + ".apk"))
        # except OSError as e:
        #    logger.warn(e)


@app.route('/login', methods=["POST"])
def login():
    user_service.login(request.form)
    next = request.args.get('next')
    return _json_redirect(next if _is_safe_url(next) else url_for('show_index'))


def _is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return target and test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


@app.route('/register', methods=['POST'])
def register():
    user_service.add(request.form)
    return _json_redirect(url_for('show_index'))


@login_required
@app.route("/logout", methods=["POST"])
def logout():
    user_service.logout()
    return _json_redirect(url_for('show_index'))


@login_required
@app.route('/scenario/<id>', methods=['PUT'])
def edit_scenario(id):
    scenario_settings_service.edit(id, request.form)
    return _json_redirect(url_for('show_scenario', id=id, edit_success=True))


@login_required
@app.route('/scenario', methods=['POST'])
def add_scenario():
    sc = scenario_settings_service.add(request.form)
    return _json_redirect(url_for('show_settings', added_scenario=sc.id))


@login_required
@app.route('/scenario/<id>', methods=['DELETE'])
def delete_scenario(id):
    scenario_settings_service.delete(id)
    return _json_redirect(url_for('show_settings', deleted_scenario=id))


@login_required
@app.route('/certificate/<id>', methods=['PUT'])
def edit_certificate(id):
    certificate_service.edit(id, request.form)
    return _json_redirect(url_for('show_certificate', id=id, edit_success=True))


@login_required
@app.route('/certificate', methods=['POST'])
def add_certificate():
    c = certificate_service.add(request.form)
    return _json_redirect(url_for('show_settings', added_certificate=c.id))


@login_required
@app.route('/certificate/<id>', methods=['DELETE'])
def delete_certificate(id):
    certificate_service.delete(id)
    return _json_redirect(url_for('show_settings', deleted_certificate=id))


def _json_redirect(url):
    return jsonify({'redirect': url})


def _json_poll_redirect(url, html=None):
    if html:
        return jsonify({'poll_redirect': url, 'html': html})
    return jsonify({'poll_redirect': url})


def _json_poll_redirects(urls, html=None):
    if html:
        return jsonify({'poll_redirects': urls, 'html': html})
    return jsonify({'poll_redirects': urls})


# ---- Error handlers ----

@app.errorhandler(FormError)
def handle_form_error(error):
    return jsonify(error.json_dict()), 400


@app.errorhandler(LoginError)
def handle_login_error(error):
    return jsonify(error.json_dict()), 400


@app.errorhandler(FieldExistsError)
def handle_field_exists_error(error):
    return jsonify(error.json_dict()), 400


@app.errorhandler(EntityNotExistsError)
def handle_entity_not_exists_error(error):
    return jsonify(error.json_dict()), 400


if __name__ == '__main__':
    create_db()
    fill_db()
    app.run(host='0.0.0.0', threaded=True)
    drop_db()
