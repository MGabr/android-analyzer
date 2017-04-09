from app import app, db
from models.default_settings import add_default_settings
from flask_testing import TestCase


class AppTest(TestCase):

    def create_app(self):
        app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///test.db"
        return app

    # Enable setUp and tearDown method inheritance behavior like in junit
    # From https://gist.github.com/twolfson/13f5f5784f67fd49b245
    # Inspired via http://stackoverflow.com/questions/1323455/python-unit-test-with-base-and-sub-class/17696807#17696807
    @classmethod
    def setUpClass(cls):
        if cls is not AppTest and cls.setUp is not AppTest.setUp:
            orig_setUp = cls.setUp

            def setUpOverride(self, *args, **kwargs):
                AppTest.setUp(self)
                return orig_setUp(self, *args, **kwargs)

            cls.setUp = setUpOverride

        if cls is not AppTest and cls.tearDown is not AppTest.tearDown:
            orig_tearDown = cls.tearDown

            def tearDownOverride(self, *args, **kwargs):
                orig_tearDown(self, *args, **kwargs)
                return AppTest.tearDown(self)

            cls.tearDown = tearDownOverride

    def setUp(self):
        db.create_all()
        add_default_settings()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
