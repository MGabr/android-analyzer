from tests.app_test import AppTest
from src.services.user_service import login, logout, add
from src.services.errors import LoginError, FieldExistsError, FormError
from flask_login import current_user


class UserServiceTest(AppTest):

    def setUp(self):
        logout()

    def test_login(self):
        form = {'username': 'test', 'password': 'password'}
        login(form)
        self.assertEqual(current_user.username, 'test')

    def test_login__required(self):
        form = {}
        self.assertRaises(FormError, login, form=form)

    def test_login__passworderror(self):
        form = {'username': 'test', 'password': 'pass'}
        self.assertRaises(LoginError, login, form=form)

    def test_login__usernameerror(self):
        form = {'username': 'test2', 'password': 'password'}
        self.assertRaises(LoginError, login, form=form)

    def test_add(self):
        form = {'username': 'test2', 'password': 'password'}
        add(form)
        self.assertEqual(current_user.username, 'test2')

    def test_add__error(self):
        form = {'username': 'test', 'password': 'password'}
        self.assertRaises(FieldExistsError, add, form=form)

    def test_logout(self):
        self.assertTrue(current_user.is_anonymous)
