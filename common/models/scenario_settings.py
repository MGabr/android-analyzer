from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Enum
from sqlalchemy.orm import relationship

from common.models.sys_certificates_table import sys_certificates_table
from common.models.user_certificates_table import user_certificates_table
from common.models.vuln_type import VulnType
from common.db_base import Base


class ScenarioSettings(Base):
    __tablename__ = 'scenario_settings'
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True)
    vuln_type = Column(Enum(VulnType))
    mitm_certificate_id = Column(Integer, ForeignKey('certificates.id'))
    mitm_certificate = relationship('Certificate',)
    sys_certificates = relationship('Certificate',
                                    secondary=sys_certificates_table,
                                    back_populates='scenario_settings_as_sys')
    user_certificates = relationship('Certificate',
                                     secondary=user_certificates_table,
                                     back_populates='scenario_settings_as_user')
    info_message = Column(String(2048))
    is_default = Column(Boolean, default=True)
    enabled = Column(Boolean, default=True)
    report_http = Column(Boolean, default=True)
    strace = Column(Boolean, default=False)
    add_upstream_certs = Column(Boolean, default=False)
    user_id = Column(String(64), ForeignKey('users.username'))
    user = relationship('User', back_populates='scenarios')

    def get_sys_certificates_ids(self):
        return [s.id for s in self.sys_certificates]

    def get_user_certificates_ids(self):
        return [u.id for u in self.user_certificates]

    def __json__(self):
        return {
            'id': self.id,
            'name': self.name,
            'vuln_type': self.vuln_type,
            'mitm_certificate': self.mitm_certificate,
            'sys_certificates': self.sys_certificates,
            'user_certificates': self.user_certificates,
            'info_message': self.info_message,
            'is_default': self.is_default,
            'enabled': self.enabled,
            'report_http': self.report_http,
            'strace': self.strace,
            'add_upstream_certs': self.add_upstream_certs,
            'user': self.user}