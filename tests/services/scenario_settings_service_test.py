from tests.app_test import AppTest
from models.scenario_settings import ScenarioSettings
from models.vuln_type import VulnType
from models.certificate import Certificate
from app import db
from services.scenario_settings_service import edit, add, delete
from services.form_error import FormError


class ScenarioSettingsTest(AppTest):

    def setUp(self):
        self.mitm_certificate = Certificate.query.get(1)
        self.sys_certificates = Certificate.query.filter(Certificate.id.in_([1, 2])).all()
        self.scenario = ScenarioSettings(
            vuln_type=VulnType.hostname_verifier,
            mitm_certificate=self.mitm_certificate,
            sys_certificates=self.sys_certificates,
            info_message='This is an info message for a non-default scenario',
            is_default=False,
            enabled=True)

        db.session.add(self.scenario)
        db.session.commit()

    def tearDown(self):
        ScenarioSettings.query.filter(ScenarioSettings.id == self.scenario.id).delete()

    def test_edit(self):
        form = {
            'vuln_type': VulnType.web_view_client.value,
            'mitm_certificate': 2,
            'sys_certificates': [],
            'user_certificates': [1, 2],
            'info_message': 'This is a changed info message'
        }
        edit(self.scenario.id, form)

        sc = ScenarioSettings.query.get(self.scenario.id)
        self.assertEqual(sc.vuln_type, VulnType.web_view_client)
        self.assertEqual(sc.mitm_certificate, Certificate.query.get(2))
        self.assertEqual(sc.sys_certificates, [])
        self.assertEqual(sc.user_certificates, Certificate.query.filter(Certificate.id.in_([1, 2])).all())
        self.assertFalse(sc.enabled)
        self.assertEqual(sc.info_message, 'This is a changed info message')

    def test_edit__required(self):
        form = {'vuln_type': VulnType.web_view_client.value}
        self.assertRaises(FormError, edit, form=form, id=self.scenario.id)

    def test_edit__default(self):
        pass

    def test_add(self):
        form = {
            'vuln_type': VulnType.web_view_client.value,
            'mitm_certificate': 2,
            'sys_certificates': [],
            'user_certificates': [1, 2],
            'info_message': 'This is an info message',
            'enabled': True
        }
        added_sc = add(form)

        sc = ScenarioSettings.query.get(added_sc.id)
        self.assertEqual(sc.vuln_type, VulnType.web_view_client)
        self.assertEqual(sc.mitm_certificate, Certificate.query.get(2))
        self.assertEqual(sc.sys_certificates, [])
        self.assertEqual(sc.user_certificates, Certificate.query.filter(Certificate.id.in_([1, 2])).all())
        self.assertTrue(sc.enabled)
        self.assertEqual(sc.info_message, 'This is an info message')

    def test_add__required(self):
        form = {
            'vuln_type': VulnType.web_view_client.value,
            'sys_certificates': [],
            'user_certificates': [1, 2],
            'info_message': 'This is an info message',
            'enabled': True
        }
        self.assertRaises(FormError, add, form=form)

    def test_delete(self):
        delete(self.scenario.id)

        sc = ScenarioSettings.query.get(self.scenario.id)
        self.assertIsNone(sc)

    def test_delete__default(self):
        pass
