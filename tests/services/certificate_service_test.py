import os
import unittest

from src.app import db
from src.definitions import CERTS_DIR
from src.models.certificate import Certificate
from src.services.errors import FormError
from src.services.certificate_service import edit, add, delete
from tests.app_test import AppTest


class CertificateServiceTest(AppTest):

    def setUp(self):
        self._create_test_certificate_file()
        self._create_certificates()

    def _create_test_certificate_file(self):
        self.test_certname = 'cert-test.pem'
        self.test_certpath = CERTS_DIR + self.test_certname

        copyfrom_cert = CERTS_DIR + 'default/cert.pem'
        copyfrom_cert_content = open(copyfrom_cert).read()

        open(self.test_certpath, 'w').write(copyfrom_cert_content)

    def _create_certificates(self):
        self.certificate = Certificate(
            name="Added non-default certificate",
            is_default=False,
            description="This is an added non-default certificate without further settings")
        self.certificate_w_cert = Certificate(
            name='Added non-default certificate with custom cert',
            is_default=False,
            custom_cert=self.test_certname)

        db.session.add(self.certificate)
        db.session.add(self.certificate_w_cert)
        db.session.commit()

    def tearDown(self):
        for f in [f for f in os.listdir(CERTS_DIR) if f.endswith(".pem")]:
            try:
                os.remove(CERTS_DIR + f)
            except OSError:
                pass

        db.session.delete(self.certificate)
        db.session.delete(self.certificate_w_cert)
        db.session.commit()

    def test_edit(self):
        form = {'name': 'Changed name', 'description': 'Changed description'}
        edit(self.certificate.id, form)

        c = Certificate.query.get(self.certificate.id)
        self.assertEqual(c.name, 'Changed name')
        self.assertEqual(c.description, 'Changed description')

    def test_edit__new_cert(self):
        form = {
            'name': 'Added non-default certificate',
            'custom_cert': self._read_cert(self.test_certname)
        }
        edit(self.certificate.id, form)

        c = Certificate.query.get(self.certificate.id)
        cert_filename = 'cert-{id}.pem'.format(id=self.certificate.id)
        self.assertEqual(c.custom_cert, cert_filename)
        self._assertCertExists(cert_filename)

    def test_edit__changed_cert(self):
        pass

    def test_edit__required(self):
        form = {'description': 'Changed description'}
        self.assertRaises(FormError, edit, id=self.certificate.id, form=form)

    def test_edit__default(self):
        pass

    def test_add(self):
        form = {
            'name': 'New name',
            'description': 'New description',
            'custom_cert': self._read_cert(self.test_certname),
            'custom_cert_domain': 'www.domain.com',
            'custom_ca': self._read_cert(self.test_certname)
        }
        added_c = add(form)

        c = Certificate.query.get(added_c.id)
        self.assertEqual(c.name, 'New name')
        self.assertEqual(c.description, 'New description')

        cert_filename = 'cert-{id}.pem'.format(id=c.id)
        self.assertEqual(c.custom_cert, cert_filename)
        self._assertCertExists(cert_filename)

        self.assertEqual(c.custom_cert_domain, 'www.domain.com')

        ca_filename = 'ca-{id}.pem'.format(id=c.id)
        self.assertEqual(c.custom_ca, ca_filename)
        self._assertCertExists(ca_filename)

    def test_add__required(self):
        form = {'description': 'New description'}
        self.assertRaises(FormError, add, form=form)

    def test_delete(self):
        delete(self.certificate.id)

        c = Certificate.query.get(self.certificate.id)
        self.assertIsNone(c)

    def test_delete__cert(self):
        delete(self.certificate_w_cert.id)

        c = Certificate.query.get(self.certificate_w_cert.id)
        self.assertIsNone(c)
        self._assertCertNotExists(self.test_certpath)

    def test_delete_default(self):
        pass

    def _read_cert(self, certname):
        with open(CERTS_DIR + certname) as certfile:
            return certfile.read()

    def _assertCertExists(self, filename):
        self.assertTrue(os.path.exists(CERTS_DIR + filename))

    def _assertCertNotExists(self, filename):
        self.assertFalse(os.path.exists(CERTS_DIR + filename))

if __name__ == '__main__':
    unittest.main()
