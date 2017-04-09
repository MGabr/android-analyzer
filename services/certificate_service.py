import os
from models.certificate import Certificate
from app import db
from services.form_error import FormError, FieldRequiredError
from definitions import CERTS_DIR


def edit(id, form):
    _check_form(form)

    certificate = Certificate.query.get(id)
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
    _check_form(form)

    certificate = Certificate(
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


def _check_form(form):
    # check if key exists and not empty string
    if 'name' not in form or not form['name']:
        field_errors = list()
        field_errors += [FieldRequiredError('name')]
        raise FormError(field_errors)
    # TODO: name unique check
