from flask import Flask, request, flash, redirect, url_for, render_template, session
from flask_uploads import UploadSet, configure_uploads
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from analysis.analysis import analyse
from models.default_settings import default_scenarios, default_certificates
from services.settings_service import get_certificates, get_vulnerability_types
import socket
import os



# patch http://stackoverflow.com/a/25536820
socket.socket._bind = socket.socket.bind
def my_socket_bind(self, *args, **kwargs):
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return socket.socket._bind(self, *args, **kwargs)
socket.socket.bind = my_socket_bind
#

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
SQLAlchemy(app)

app.secret_key = 'lilian'
#SESSION_TYPE = 'sqlalchemy'
#Session(app)

app.config['UPLOADED_APKS_DEST'] = 'input_apks'
apks = UploadSet('apks', ('apk',))
configure_uploads(app, (apks,))


@app.route('/index')
def show_index():
    return render_template('index.html')


@app.route('/login')
def show_login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    # check request.form['username'], request.form['password']
    session['username'] = request.form['username']
    return render_template('index.html')


@app.route('/register')
def show_register():
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def register():
    # register user with request.form['username'], request.form['password']
    return render_template('index.html')


@app.route('/settings')
def show_settings():
    return render_template('settings.html', scenarios=default_scenarios, certificates=default_certificates)


@app.route('/scenario/<id>')
def show_scenario(id):
    scenario = None
    for sc in default_scenarios:
        if str(sc.id) == id:
            scenario = sc
            break
    return render_template('scenario.html', sc=scenario, vuln_types=get_vulnerability_types(), certs=get_certificates())


@app.route('/certificate/<id>')
def show_certificate(id):
    certificate = None
    for c in default_certificates:
        if str(c.id) == id:
            certificate = c
            break
    return render_template('certificate.html', c=certificate)


@app.route('/apk', methods=['POST'])
def upload_apk():
    if 'apk' in request.files:
        filename = apks.save(request.files['apk'])
        filename = filename.replace('.apk', '')
        log_analysis_results = analyse(filename)
        os.remove(os.path.join(app.config['UPLOADED_APKS_DEST'], filename + ".apk"))
    else:
        flash("APK upload failed.")
    return render_template('index.html', log_analysis_results=log_analysis_results)


@app.context_processor
def processor():

    def display_comma_joined(set):
        return ", ".join(set)

    def row_class_for_result(log_analysis_result):
        if log_analysis_result.is_vulnerable():
            return "danger"
        elif log_analysis_result.dynamic_analysis_result.scenario.is_statically_vulnerable():
            return "warning"
        else:
            return "success"
        # TODO: for crashed analysis

    def glyphicon_for_static_result(log_analysis_result):
        if log_analysis_result.is_vulnerable():
            return "glyphicon glyphicon-alert text-danger"
        elif log_analysis_result.dynamic_analysis_result.scenario.is_statically_vulnerable():
            return "glyphicon glyphicon-alert text-danger"
        else:
            return "glyphicon glyphicon-ok text-success"
        # TODO: for crashed analysis

    def glyphicon_for_dynamic_result(log_analysis_result):
        if log_analysis_result.is_vulnerable():
            return "glyphicon glyphicon-alert text-danger"
        elif log_analysis_result.dynamic_analysis_result.scenario.is_statically_vulnerable():
            return "glyphicon glyphicon-ok text-success"
        else:
            return "glyphicon glyphicon-minus text-muted"
            # TODO: for crashed analysis

    def vulntype_for_result(log_analysis_result):
        log_analysis_result.dynamic_analysis_result.scenario.scenario_settings.vuln_type
        return

    def connected_hostnames_for_result(log_analysis_result):
        return

    def certificate_name_for_result(log_analysis_result):
        return

    def trusted_certificate_names_for_result(log_analysis_result):
        return

    return dict(
        display_comma_joined=display_comma_joined,
        row_class_for_result=row_class_for_result,
        glyphicon_for_static_result=glyphicon_for_static_result,
        glyphicon_for_dynamic_result=glyphicon_for_dynamic_result)


if __name__ == '__main__':
    # flask default port is 5000, but adb also runs on 5000
    app.run(host='127.0.0.1', port=4003, threaded=True)
