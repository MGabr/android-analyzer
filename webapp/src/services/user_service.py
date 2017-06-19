import bcrypt
from flask_login import login_user, current_user, logout_user

from src.app import db
from src.create_db import add_default_settings
from common.models.user import User
from src.services.errors import LoginError, FieldExistsError, check_form


required_fields = ['username', 'password']


def login(form):
    check_form(form, required_fields)

    user = user_loader(form['username'])
    if not user or not bcrypt.checkpw(form['password'].encode('utf-8'), user.password):
        raise LoginError()

    user.is_authenticated = True
    db.session.add(user)
    db.session.commit()
    login_user(user, remember=True)


def logout():
    current_user.is_authenticated = False
    db.session.add(current_user)
    db.session.commit()
    logout_user()


def add(form):
    check_form(form, required_fields)

    if user_loader(form['username']):
        raise FieldExistsError('User', 'username')

    hashed_password = bcrypt.hashpw(form['password'].encode('utf-8'), bcrypt.gensalt())
    user = User(username=form['username'], password=hashed_password, is_authenticated=True)  # login on registration
    db.session.add(user)
    db.session.commit()
    login_user(user, remember=True)  # login on registration

    add_default_settings(user)  # add default settings for user


def user_loader(user_id):
    return User.query.filter(User.username == user_id).first()

