from src.app import db
from src.models.sys_certificates_table import sys_certificates_table
from src.models.user_certificates_table import user_certificates_table
from src.models.vuln_type import VulnType


class ScenarioSettings(db.Model):
    __tablename__ = 'scenario_settings'
    id = db.Column(db.Integer, primary_key=True)
    vuln_type = db.Column(db.Enum(VulnType))
    mitm_certificate_id = db.Column(db.Integer, db.ForeignKey('certificates.id'))
    mitm_certificate = db.relationship('Certificate',)
    sys_certificates = db.relationship('Certificate',
                                    secondary=sys_certificates_table,
                                    back_populates='scenario_settings_as_sys')
    user_certificates = db.relationship('Certificate',
                                     secondary=user_certificates_table,
                                     back_populates='scenario_settings_as_user')
    info_message = db.Column(db.String(2048))
    is_default = db.Column(db.Boolean, default=True)
    enabled = db.Column(db.Boolean, default=True)
    add_upstream_certs = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.username'))
    user = db.relationship('User', back_populates='scenarios')

    def get_sys_certificates_ids(self):
        return [s.id for s in self.sys_certificates]

    def get_user_certificates_ids(self):
        return [u.id for u in self.user_certificates]

    def __json__(self):
        return {
            'id': self.id,
            'vuln_type': self.vuln_type,
            'mitm_certificate': self.mitm_certificate,
            'sys_certificates': self.sys_certificates,
            'user_certificates': self.user_certificates,
            'info_message': self.info_message,
            'is_default': self.is_default,
            'enabled': self.enabled,
            'add_upstream_certs': self.add_upstream_certs,
            'user': self.user}