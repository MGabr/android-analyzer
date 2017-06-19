from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, UnicodeText
from sqlalchemy.orm import relationship

from common.models.sys_certificates_table import sys_certificates_table
from common.models.user_certificates_table import user_certificates_table
from common.db_base import Base


class Certificate(Base):
    __tablename__ = 'certificates'
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True)
    is_default = Column(Boolean, default=True)
    description = Column(String(2048))
    custom_cert = Column(UnicodeText())
    custom_cert_domain = Column(String(128))
    custom_ca = Column(UnicodeText())
    user_id = Column(String(64), ForeignKey('users.username'))
    user = relationship('User')

    scenario_settings_as_sys = relationship('ScenarioSettings',
                                            secondary=sys_certificates_table,
                                            back_populates='sys_certificates')
    scenario_settings_as_user = relationship('ScenarioSettings',
                                             secondary=user_certificates_table,
                                             back_populates='user_certificates')

    def custom_cert_content(self):
        return self.custom_cert

    def custom_ca_content(self):
        return self.custom_ca

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