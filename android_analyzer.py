from flask import request, flash, render_template, session, url_for, jsonify
import socket
import os
from app import app, db, apks
from analysis.analysis import analyse
from models.certificate import Certificate
from models.scenario_settings import ScenarioSettings
from models.vuln_type import VulnType
from services import certificate_service
from services import scenario_settings_service
from models.default_settings import add_default_settings
from services.form_error import FormError


# Don't remove this
import context_processors


# patch http://stackoverflow.com/a/25536820
socket.socket._bind = socket.socket.bind
def my_socket_bind(self, *args, **kwargs):
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return socket.socket._bind(self, *args, **kwargs)
socket.socket.bind = my_socket_bind
#


@app.route('/index')
def show_index():
    return render_template('index.html')


# @app.route('/login')
# def show_login():
#     return render_template('login.html')
#
#
# @app.route('/login', methods=['POST'])
# def login():
#     # check request.form['username'], request.form['password']
#     session['username'] = request.form['username']
#     return render_template('index.html')
#
#
# @app.route('/register')
# def show_register():
#     return render_template('register.html')
#
#
# @app.route('/register', methods=['POST'])
# def register():
#     # register user with request.form['username'], request.form['password']
#     return render_template('index.html')


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


@app.route('/settings')
def show_settings():
    return render_template('settings.html',
                           scenarios=ScenarioSettings.query.all(),
                           certificates=Certificate.query.all())


@app.route('/scenario/<id>', methods=['GET'])
def show_scenario(id):
    new = id == 'new'
    sc = ScenarioSettings() if new else ScenarioSettings.query.get(id)
    return render_template('scenario.html',
                           new=new,
                           sc=sc,
                           vuln_types=[v for v in VulnType],
                           certs=Certificate.query.all())


@app.route('/certificate/<id>', methods=['GET'])
def show_certificate(id):
    new = id == 'new'
    c = Certificate() if new else Certificate.query.get(id)
    return render_template('certificate.html', new=new, c=c)


# ---- REST Api for AJAX calls ----

@app.route('/scenario/<id>', methods=['PUT'])
def edit_scenario(id):
    scenario_settings_service.edit(id, request.form)
    return _json_redirect(url_for('show_scenario', id=id, edit_success=True))


@app.route('/scenario', methods=['POST'])
def add_scenario():
    sc = scenario_settings_service.add(request.form)
    return _json_redirect(url_for('show_settings', added_scenario=sc.id))


@app.route('/scenario/<id>', methods=['DELETE'])
def delete_scenario(id):
    scenario_settings_service.delete(id)
    return _json_redirect(url_for('show_settings', deleted_scenario=id))


@app.route('/certificate/<id>', methods=['PUT'])
def edit_certificate(id):
    certificate_service.edit(id, request.form)
    return _json_redirect(url_for('show_certificate', id=id, edit_success=True))


@app.route('/certificate', methods=['POST'])
def add_certificate():
    c = certificate_service.add(request.form)
    return _json_redirect(url_for('show_settings', added_certificate=c.id))


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


if __name__ == '__main__':
    # flask default port is 5000, but adb also runs on 5000
    db.create_all()
    add_default_settings()
    app.run(host='127.0.0.1', port=4009, threaded=True)
    db.drop_all()