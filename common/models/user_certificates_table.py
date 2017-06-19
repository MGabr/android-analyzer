from sqlalchemy import Table, ForeignKey, Column

from common.db_base import Base


user_certificates_table = Table(
    'user_certificates',
    Base.metadata,
    Column('scenario_settings_id', ForeignKey('scenario_settings.id'), primary_key=True),
    Column('certificate_id', ForeignKey('certificates.id'), primary_key=True)
)