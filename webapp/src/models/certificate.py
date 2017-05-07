from src.app import db
from src.definitions import CERTS_DIR
from src.models.sys_certificates_table import sys_certificates_table
from src.models.user_certificates_table import user_certificates_table


class Certificate(db.Model):
    __tablename__ = 'certificates'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    is_default = db.Column(db.Boolean, default=True)
    description = db.Column(db.String(2048))
    custom_cert = db.Column(db.String(4096))
    custom_cert_domain = db.Column(db.String(128))
    custom_ca = db.Column(db.String(4096))
    user_id = db.Column(db.Integer, db.ForeignKey('users.username'))
    user = db.relationship('User')

    scenario_settings_as_sys = db.relationship('ScenarioSettings',
                                            secondary=sys_certificates_table,
                                            back_populates='sys_certificates')
    scenario_settings_as_user = db.relationship('ScenarioSettings',
                                             secondary=user_certificates_table,
                                             back_populates='user_certificates')

    def custom_cert_content(self):
        with open(CERTS_DIR + self.custom_cert) as content:
            return content.read()

    def custom_ca_content(self):
        with open(CERTS_DIR + self.custom_ca) as content:
            return content.read()

    def __json__(self):
        return {
            'id': self.id,
            'name': self.name,
            'is_default': self.is_default,
            'description': self.description,
            'custom_cert': self.custom_cert,
            'custom_cert_domain': self.custom_cert_domain,
            'custom_ca': self.custom_ca,
            'user': self.user}