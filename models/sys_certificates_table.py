from app import db

sys_certificates_table = db.Table(
    'sys_certificates',
    db.metadata,
    db.Column('scenario_settings_id', db.ForeignKey('scenario_settings.id'), primary_key=True),
    db.Column('certificates_id', db.ForeignKey('certificates.id'), primary_key=True)
)