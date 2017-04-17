from flask_login import current_user

from src.app import db
from src.models.certificate import Certificate
from src.models.scenario_settings import ScenarioSettings
from src.models.vuln_type import VulnType
from src.services.errors import check_form, EntityNotExistsError

required_fields = ['vuln_type', 'mitm_certificate']


def edit(id, form):
    check_form(form, required_fields)

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
    check_form(form, required_fields)

    mitm_certificate, sys_certificates, user_certificates = _get_scenario_certificates(form)

    scenario = ScenarioSettings(
        user=current_user,
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


def get_of_user(id):
    scenario = ScenarioSettings.query.get(id)
    if not scenario.is_default and not scenario.user == current_user:
        raise EntityNotExistsError('ScenarioSettings', id)
    return scenario


def get_all_of_user():
    default_scenarios = ScenarioSettings.query.filter(ScenarioSettings.is_default).all()
    if current_user.is_anonymous:
        return default_scenarios
    return current_user.scenarios + default_scenarios


def get_all_enabled_of_user():
    default_scenarios = ScenarioSettings.query.filter(ScenarioSettings.is_default, ScenarioSettings.enabled).all()
    if current_user.is_anonymous:
        return default_scenarios
    return [s for s in current_user.scenarios if s.enabled] + default_scenarios


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
