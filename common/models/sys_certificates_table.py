from sqlalchemy import Table, ForeignKey, Column

from common.db_base import Base


sys_certificates_table = Table(
    'sys_certificates',
    Base.metadata,
    Column('scenario_settings_id', ForeignKey('scenario_settings.id'), primary_key=True),
    Column('certificates_id', ForeignKey('certificates.id'), primary_key=True)
)