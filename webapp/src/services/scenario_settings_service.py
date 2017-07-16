from flask_login import current_user

from common.models.certificate import Certificate
from common.models.scenario_settings import ScenarioSettings
from common.models.vuln_type import VulnType
from src.app import db
from src.services.errors import check_form, EntityNotExistsError, FieldExistsError

required_fields = ['name', 'vuln_type', 'mitm_certificate']


def edit(id, form):
    scenario = ScenarioSettings.query.get(id)

    if scenario:
        check_form(form, required_fields)

        mitm_certificate, sys_certificates, user_certificates = _get_scenario_certificates(form)

        scenario.enabled = 'enabled' in form
        scenario.num_activities_limit = form.get('num_activities_limit')
        scenario.name = form['name']
        scenario.vuln_type = VulnType(form['vuln_type'])
        scenario.mitm_certificate = mitm_certificate
        scenario.sys_certificates = sys_certificates
        # scenario.user_certificates = user_certificates
        scenario.info_message = form.get('info_message')
        scenario.report_http = 'report_http' in form
        scenario.strace = 'strace' in form
        scenario.add_upstream_certs = 'add_upstream_certs' in form
        scenario.only_exported_activities = 'only_exported_activities' in form

    db.session.commit()

    return scenario


def add(form):
    check_form(form, required_fields)

    mitm_certificate, sys_certificates, user_certificates = _get_scenario_certificates(form)

    scenario = ScenarioSettings(
        num_activities_limit=form.get('num_activities_limit'),
        user=current_user,
        name=form['name'],
        vuln_type=VulnType(form['vuln_type']),
        mitm_certificate=mitm_certificate,
        sys_certificates=sys_certificates,
        # user_certificates=user_certificates,
        info_message=form.get('info_message'),
        is_default=False,
        enabled='enabled' in form,
        report_http='report_http' in form,
        strace='strace' in form,
        add_upstream_certs='add_upstream_certs' in form,
        only_exported_activities='only_exported_activities' in form
    )

    db.session.add(scenario)
    db.session.commit()

    return scenario


def delete(id):
    scenario = ScenarioSettings.query.get(id)
    if not scenario.is_default:
        db.session.delete(scenario)
        db.session.commit()


def get_of_user(id, current_user=current_user):
    scenarios = [s for s in current_user.scenarios if s.id == int(id)]
    if not scenarios:
        raise EntityNotExistsError('ScenarioSettings', id)
    return scenarios[0]


def get_all_of_user(current_user=current_user):
    return current_user.scenarios


def get_all_enabled_of_user(current_user=current_user):
    return [s for s in current_user.scenarios if s.enabled]


def _get_scenario_certificates(form):
    mitm_certificate = Certificate.query.get(form['mitm_certificate'])

    if 'sys_certificates' in form:
        sys_certificates = Certificate.query.filter(Certificate.id.in_(form.getlist('sys_certificates'))).all()
    else:
        sys_certificates = []

    # if 'user_certificates' in form:
    #     user_certificates = Certificate.query.filter(Certificate.id.in_(form.getlist('user_certificates'))).all()
    # else:
    user_certificates = []

    return mitm_certificate, sys_certificates, user_certificates
