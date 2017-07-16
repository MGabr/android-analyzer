import functools
import logging
from urlparse import urlparse, urljoin

from flask import request, render_template, url_for, jsonify, send_file
from flask_login import login_required, current_user
from flask_socketio import disconnect, join_room

from common.models.certificate import Certificate
from common.models.scenario_settings import ScenarioSettings
from common.models.vuln_type import VulnType
from services import scenario_settings_service
from src.app import app, login_manager, socketio
from src.create_db import create_db, reset_default_settings
from src.definitions import INPUT_APK_DIR
from src.services import analysis_service
from src.services import certificate_service
from src.services import user_service
from src.services.errors import FormError, LoginError, FieldExistsError, EntityNotExistsError

logging.basicConfig(level=logging.INFO)


login_manager.login_view = "show_login"


@login_manager.user_loader
def user_loader(user_id):
    return user_service.user_loader(user_id)


# initialize db
create_db()


# ---- Views ----

@app.route('/index', methods=['GET'])
def show_index():
    return render_template('index.html')


# same page as register
@app.route('/login', methods=['GET'])
def show_login():
    return render_template('login.html')


@app.route('/settings', methods=['GET'])
@login_required
def show_settings():
    return render_template('settings.html',
                           scenarios=scenario_settings_service.get_all_of_user(),
                           certificates=certificate_service.get_all_of_user())


@app.route('/scenario/<id>', methods=['GET'])
@login_required
def show_scenario(id):
    new = id == 'new'
    sc = ScenarioSettings() if new else scenario_settings_service.get_of_user(id)
    return render_template('scenario.html',
                           new=new,
                           sc=sc,
                           vuln_types=[v for v in VulnType],
                           certs=certificate_service.get_all_of_user(),
                           sys_certs=certificate_service.get_all_possible_sys_of_user())


@app.route('/certificate/<id>', methods=['GET'])
@login_required
def show_certificate(id):
    new = id == 'new'
    c = Certificate() if new else certificate_service.get_of_user(id)
    return render_template('certificate.html', new=new, c=c)


# ---- Main API calls ----


@app.route('/analysis', methods=['POST'])
@login_required
def start_analysis():
    html = analysis_service.start_analysis(request.files)
    if html:
        return jsonify({'html': html})
    else:
        return _json_error()


@app.route('/apk/<filename>', methods=['GET'])
def get_apk(filename):
    return send_file(INPUT_APK_DIR + filename + ".apk")


def authenticated_only(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            disconnect()
        else:
            return f(*args, **kwargs)
    return wrapped


@socketio.on('connect')
@authenticated_only
def connect_handler():
    join_room(current_user.username)


@socketio.on('activities_analysis')
@authenticated_only
def activities_analysis_handler(json):
    analysis_service.start_activities_analysis(json['filename'], json['activities'], json['scenario_settings_id'])


# ---- Api for AJAX calls ----


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


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    user_service.logout()
    return _json_redirect(url_for('show_index'))


@app.route('/scenario/<id>', methods=['PUT'])
@login_required
def edit_scenario(id):
    scenario_settings_service.edit(id, request.form)
    return _json_redirect(url_for('show_scenario', id=id, edit_success=True))


@app.route('/scenario', methods=['POST'])
@login_required
def add_scenario():
    sc = scenario_settings_service.add(request.form)
    return _json_redirect(url_for('show_settings', added_scenario=sc.id))


@app.route('/scenario/<id>', methods=['DELETE'])
@login_required
def delete_scenario(id):
    scenario_settings_service.delete(id)
    return _json_redirect(url_for('show_settings', deleted_scenario=id))


@app.route('/certificate/<id>', methods=['PUT'])
@login_required
def edit_certificate(id):
    certificate_service.edit(id, request.form)
    return _json_redirect(url_for('show_certificate', id=id, edit_success=True))


@app.route('/certificate', methods=['POST'])
@login_required
def add_certificate():
    c = certificate_service.add(request.form)
    return _json_redirect(url_for('show_settings', added_certificate=c.id))


@app.route('/certificate/<id>', methods=['DELETE'])
@login_required
def delete_certificate(id):
    certificate_service.delete(id)
    return _json_redirect(url_for('show_settings', deleted_certificate=id))


@app.route('/settings', methods=['PUT'])
@login_required
def reset_settings():
    reset_default_settings(current_user)
    return _json_redirect(url_for('show_settings'))


def _json_redirect(url):
    return jsonify({'redirect': url})


def _json_error():
    return jsonify({'error': True}), 400


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
    socketio.run(app, host='0.0.0.0', log_output=True)
