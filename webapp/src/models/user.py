from src.app import db


class User(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String, primary_key=True)
    password = db.Column(db.LargeBinary)
    authenticated = db.Column(db.Boolean, default=False)
    scenarios = db.relationship("ScenarioSettings", back_populates="user")
    certificates = db.relationship('Certificate', back_populates="user")

    def is_active(self):
        return True

    def get_id(self):
        return self.username

    def is_authenticated(self):
        return self.authenticated

    def is_anonymous(self):
        return False

    def __json__(self):
        return {
            'username': self.username,
            'password': self.password,
            'authenticated': self.authenticated,
            'scenarios': self.scenarios,
            'certificates': self.certificates}