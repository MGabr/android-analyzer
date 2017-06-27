from flask_login import current_user

from common.models.certificate import Certificate
from src.app import db
from src.services.errors import check_form, FieldExistsError, EntityNotExistsError

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
        certificate.custom_cert = form.get('custom_cert')
        certificate.custom_ca = form.get('custom_ca')

        db.session.commit()

    return certificate


def add(form):
    check_form(form, required_fields)
    _check_name_exists(form)

    certificate = Certificate(
        user=current_user,
        name=form['name'],
        description=form.get('description'),
        custom_cert_domain=form.get('custom_cert_domain'),
        custom_cert=form.get('custom_cert'),
        custom_ca=form.get('custom_ca'),
        is_default=False)

    db.session.add(certificate)
    db.session.commit()

    return certificate


def _check_name_exists(form):
    if Certificate.query.filter(Certificate.name == form['name']).first():
        raise FieldExistsError('Certificate', 'name')


def delete(id):
    certificate = Certificate.query.get(id)
    if not certificate.is_default:
        db.session.delete(certificate)
        db.session.commit()


def get_of_user(id):
    certificates = [c for c in current_user.certificates]
    if not certificates:
        raise EntityNotExistsError('Certificate', id)
    return certificates[0]


def get_all_of_user():
    return current_user.certificates


def get_all_possible_sys_of_user():
    return [c for c in current_user.certificates if c.custom_ca]
