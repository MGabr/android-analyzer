from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_uploads import UploadSet, configure_uploads
from src.definitions import INPUT_APK_DIR
from flask_login.login_manager import LoginManager
from celery import Celery


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///android-analyzer.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

app.secret_key = 'lilian'
login_manager = LoginManager(app)

app.config['UPLOADED_APKS_DEST'] = INPUT_APK_DIR
apks = UploadSet('apks', ('apk',))
configure_uploads(app, (apks,))

app.config['CELERY_BROKER_URL'] = 'amqp://admin:mypass@rabbit//'
app.config['CELERY_RESULT_BACKEND'] = 'rpc://'
app.config['CELERY_ROUTES'] = {
    'static_analysis_task': {'queue': 'static_queue'},
    'dynamic_analysis_task': {'queue': 'dynamic_queue'}}


def make_celery(app):
    celery = Celery(broker=app.config['CELERY_BROKER_URL'], backend=app.config['CELERY_RESULT_BACKEND'])
    celery.conf.update(app.config)
    TaskBase = celery.Task

    class ContextTask(TaskBase):
        abstract = True

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)

    celery.Task = ContextTask
    return celery
