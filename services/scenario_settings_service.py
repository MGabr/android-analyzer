from app import db
from models.scenario_settings import ScenarioSettings
from models.vuln_type import VulnType
from models.certificate import Certificate
from services.form_error import FieldRequiredError, FormError


def edit(id, form):
    _check_form(form)

    scenario = ScenarioSettings.query.get(id)
    if not scenario.is_default:
        mitm_certificate, sys_certificates, user_certificates = _get_scenario_certificates(form)

        scenario.vuln_type = VulnType(form['vuln_type'])
        scenario.mitm_certificate = mitm_certificate
        scenario.sys_certificates = sys_certificates
        scenario.user_certificates = user_certificates
        scenario.info_message = form.get('info_message')
        scenario.enabled='enabled' in form

        db.session.commit()

    return scenario


def add(form):
    _check_form(form)

    mitm_certificate, sys_certificates, user_certificates = _get_scenario_certificates(form)

    scenario = ScenarioSettings(
        vuln_type=VulnType(form['vuln_type']),
        mitm_certificate=mitm_certificate,
        sys_certificates=sys_certificates,
        user_certificates=user_certificates,
        info_message=form.get('info_message'),
        is_default=False,
        enabled='enabled' in form
    )

    db.session.add(scenario)
    db.session.commit()

    return scenario


def delete(id):
    scenario = ScenarioSettings.query.get(id)
    if not scenario.is_default:
        db.session.delete(scenario)
        db.session.commit()


def _check_form(form):
    field_errors = list()
    for required_field in ['vuln_type', 'mitm_certificate']:
        # check if key exists and not empty string
        if required_field not in form or not form[required_field]:
            field_errors += [FieldRequiredError(required_field)]
    if field_errors:
        raise FormError(field_errors)


def _get_scenario_certificates(form):
    mitm_certificate = Certificate.query.get(form['mitm_certificate'])

    if 'sys_certificates' in form:
        sys_certificates = Certificate.query.filter(Certificate.id.in_(form.getlist('sys_certificates'))).all()
    else:
        sys_certificates = []

    if 'user_certificates' in form:
        user_certificates = Certificate.query.filter(Certificate.id.in_(form.getlist('user_certificates'))).all()
    else:
        user_certificates = []

    return mitm_certificate, sys_certificates, user_certificates
