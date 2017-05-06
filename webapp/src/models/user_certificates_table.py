from src.app import db

user_certificates_table = db.Table(
    'user_certificates',
    db.metadata,
    db.Column('scenario_settings_id', db.ForeignKey('scenario_settings.id'), primary_key=True),
    db.Column('certificate_id', db.ForeignKey('certificates.id'), primary_key=True)
)