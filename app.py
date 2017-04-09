from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_uploads import UploadSet, configure_uploads
from definitions import INPUT_APK_DIR

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///android-analyzer.db'
db = SQLAlchemy(app)

app.secret_key = 'lilian'
#SESSION_TYPE = 'sqlalchemy'
#Session(app)

app.config['UPLOADED_APKS_DEST'] = INPUT_APK_DIR
apks = UploadSet('apks', ('apk',))
configure_uploads(app, (apks,))
