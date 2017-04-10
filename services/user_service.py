from models.user import User
import bcrypt
from app import db
from flask_login import login_user, current_user, logout_user
from login_error import LoginError
from exists_error import ExistsError
from form_error import check_form


required_fields = ['username', 'password']


def login(form):
    check_form(form, required_fields)

    user = user_loader(form['username'])
    if not user or not bcrypt.checkpw(form['password'].encode('utf-8'), user.password.encode('utf-8')):
        raise LoginError()

    user.authenticated = True
    db.session.add(user)
    db.session.commit()
    login_user(user, remember=True)


def logout():
    user = current_user
    user.authenticated = False
    db.session.add(user)
    db.session.commit()
    logout_user()


def add(form):
    check_form(form, required_fields)

    if user_loader(form['username']):
        raise ExistsError('User', 'username')

    hashed_password = bcrypt.hashpw(form['password'].encode('utf-8'), bcrypt.gensalt())
    user = User(username=form['username'], password=hashed_password, authenticated=True)  # login on registration
    db.session.add(user)
    db.session.commit()
    login_user(user, remember=True)  # login on registration


def user_loader(user_id):
    return User.query.filter(User.username == user_id).first()

