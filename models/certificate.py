from sys_certificates_table import sys_certificates_table
from user_certificates_table import user_certificates_table
from app import db


class Certificate(db.Model):
    __tablename__ = 'certificates'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    is_default = db.Column(db.Boolean, default=True)
    description = db.Column(db.String(2048))
    custom_cert = db.Column(db.String(4096))
    custom_cert_domain = db.Column(db.String(128))
    custom_ca = db.Column(db.String(4096))

    scenario_settings_as_sys = db.relationship('ScenarioSettings',
                                            secondary=sys_certificates_table,
                                            back_populates='sys_certificates')
    scenario_settings_as_user = db.relationship('ScenarioSettings',
                                             secondary=user_certificates_table,
                                             back_populates='user_certificates')