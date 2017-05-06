import unittest

from webapp.tests.app_test import AppTest


class AndroidAnalyzerTest(AppTest):

    def test_show_index(self):
        rv = self.app.get('/index')
        assert 'Upload and analyze APK file' in rv.data

    def test_show_settings(self):
        rv = self.app.get('/settings')

        msg = 'Not all scenarios present'
        self.assertIn('HostnameVerifier', rv.data, msg=msg)
        self.assertIn('TrustManager', rv.data, msg=msg)
        self.assertIn('WebViewClient', rv.data, msg=msg)

        msg = 'Not all certificates present'
        self.assertIn('Signed on-the-fly by unknown CA', rv.data, msg=msg)
        self.assertIn('Self-signed with fixed hostname', rv.data, msg=msg)
        self.assertIn('Signed on-the-fly by an untrusted CA', rv.data, msg=msg)

    def test_show_scenario(self):
        rv = self.app.get('/scenario/1')

        self.assertRegexpMatches(rv.data, '.*checked.*checked', msg='Not default and enabled')

    def test_show_scenario__not_existing(self):
        pass

    def test_edit_scenario(self):
        pass

    def test_edit_scenario__not_existing(self):
        pass

    def test_edit_scenario__default(self):
        pass

    def test_add_scenario(self):
        pass

    def test_show_certificate(self):
        pass

    def test_show_certificate__not_existing(self):
        pass

    def test_edit_certificate(self):
        pass

    def test_edit_certificate__not_existing(self):
        pass

    def test_edit_certificate__default(self):
        pass

    def test_add_certificate(self):
        pass


if __name__ == '__main__':
    unittest.main()