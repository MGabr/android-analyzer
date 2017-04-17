import os
import socket
from urlparse import urlparse, urljoin

from flask import request, flash, render_template, url_for, jsonify
from flask_login import login_required
from services import certificate_service
from services import scenario_settings_service
from services.errors import FormError, LoginError, FieldExistsError, EntityNotExistsError

from app import app, db, apks
from app import login_manager
from src.analysis.analysis import analyse
from src.models.certificate import Certificate
from src.models.scenario_settings import ScenarioSettings
from src.models.vuln_type import VulnType
from src.services import user_service
from src.create_db import create_db, fill_db, drop_db
from src.context_processors import context_processor


# patch http://stackoverflow.com/a/25536820
socket.socket._bind = socket.socket.bind
def my_socket_bind(self, *args, **kwargs):
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return socket.socket._bind(self, *args, **kwargs)
socket.socket.bind = my_socket_bind
#

login_manager.login_view = "show_login"


@login_manager.user_loader
def user_loader(user_id):
    return user_service.user_loader(user_id)


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


# ---- Other non-AJAX calls ----

@app.route('/apk', methods=['POST'])
def upload_apk():
    if 'apk' in request.files:
        filename = apks.save(request.files['apk'])
        filename = filename.replace('.apk', '')
        log_analysis_results = analyse(filename)
        os.remove(os.path.join(app.config['UPLOADED_APKS_DEST'], filename + ".apk"))
    else:
        flash("APK upload failed.")
    return render_template('result.html', log_analysis_results=log_analysis_results)


# ---- REST Api for AJAX calls ----

@app.route("/login", methods=["POST"])
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
    # flask default port is 5000, but adb also runs on 5000
    create_db()
    fill_db()
    app.run(host='127.0.0.1', port=4008, threaded=True)
    drop_db()
