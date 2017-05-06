import os

from flask_login import current_user
from src.app import db
from src.definitions import CERTS_DIR
from src.services.errors import check_form, FieldExistsError, EntityNotExistsError
from src.models.certificate import Certificate

required_fields = ['name']


def edit(id, form):
    check_form(form, required_fields)

    certificate = Certificate.query.get(id)

    if certificate.name != form['name']:
        _check_name_exists(form)

    if certificate and not certificate.is_default:
        certificate.name = form['name']
        certificate.description=form.get('description')
        certificate.custom_cert_domain=form.get('custom_cert_domain')
        _replace_custom_cert(certificate, form)
        _replace_custom_ca(certificate, form)

        db.session.commit()

    return certificate


def _replace_custom_cert(certificate, form):
    custom_cert_name = _custom_cert_name(certificate.id)
    custom_cert_path = CERTS_DIR + custom_cert_name

    cert_exists = os.path.exists(custom_cert_path)

    def new_cert():
        return not cert_exists and 'custom_cert' in form

    def changed_cert():
        if cert_exists:
            with open(custom_cert_path, 'r') as custom_cert_file:
                return custom_cert_file.read() != form.get('custom_cert')
        return False

    if new_cert() or changed_cert():
        with open(custom_cert_path, 'w') as custom_cert_file:
            custom_cert_file.write(form['custom_cert'])
        certificate.custom_cert = custom_cert_name


def _replace_custom_ca(certificate, form):
    custom_ca_name = _custom_ca_name(certificate.id)
    custom_ca_path = CERTS_DIR + custom_ca_name

    ca_exists = os.path.exists(custom_ca_path)

    def new_ca():
        return not ca_exists and 'custom_ca' in form

    def changed_ca():
        if ca_exists:
            with open(custom_ca_path, 'r') as custom_ca_file:
                return custom_ca_file.read() != form.get('custom_ca')
        return False

    if new_ca() or changed_ca():
        with open(custom_ca_path, 'w') as custom_ca_file:
            custom_ca_file.write(form['custom_ca'])
        certificate.custom_ca = custom_ca_name


def add(form):
    check_form(form, required_fields)
    _check_name_exists(form)

    certificate = Certificate(
        user=current_user,
        name=form['name'],
        description=form.get('description'),
        custom_cert_domain=form.get('custom_cert_domain'),
        is_default=False)

    db.session.add(certificate)
    db.session.flush()
    # now we have the certificate.id we need

    _add_custom_cert(certificate, form)
    _add_custom_ca(certificate, form)

    db.session.add(certificate)
    db.session.commit()

    return certificate


def _add_custom_cert(certificate, form):
    if 'custom_cert' in form:
        custom_cert_name = _custom_cert_name(certificate.id)

        with open(CERTS_DIR + custom_cert_name, 'w') as custom_cert_file:
            custom_cert_file.write(form['custom_cert'])

        certificate.custom_cert = custom_cert_name


def _add_custom_ca(certificate, form):
    if 'custom_ca' in form:
        custom_ca_name = _custom_ca_name(certificate.id)

        with open(CERTS_DIR + custom_ca_name, 'w') as custom_ca_file:
            custom_ca_file.write(form['custom_ca'])

        certificate.custom_ca = custom_ca_name


def _custom_cert_name(id):
    return 'cert-{id}.pem'.format(id=id)


def _custom_ca_name(id):
    return 'ca-{id}.pem'.format(id=id)


def _check_name_exists(form):
    if Certificate.query.filter(Certificate.name == form['name']).first():
        raise FieldExistsError('Certificate', 'name')


def delete(id):
    certificate = Certificate.query.get(id)
    if not certificate.is_default:
        if certificate.custom_cert:
            try:
                os.remove(CERTS_DIR + certificate.custom_cert)
            except OSError:
                pass

        if certificate.custom_ca:
            try:
                os.remove(CERTS_DIR + certificate.custom_ca)
            except OSError:
                pass

        db.session.delete(certificate)
        db.session.commit()


def get_of_user(id):
    certificate = Certificate.query.get(id)
    if not certificate.is_default and not certificate.user == current_user:
        raise EntityNotExistsError('Certificate', id)
    return certificate


def get_all_of_user():
    default_certs = Certificate.query.filter(Certificate.is_default).all()
    if current_user.is_anonymous:
        return default_certs
    return current_user.certificates + default_certs
