from sqlalchemy import Column, String, Boolean, LargeBinary
from sqlalchemy.orm import relationship

from common.db_base import Base


class User(Base):
    __tablename__ = 'users'
    username = Column(String(64), primary_key=True)
    password = Column(LargeBinary)
    is_authenticated = Column(Boolean, default=False)
    scenarios = relationship('ScenarioSettings', back_populates="user")
    certificates = relationship('Certificate', back_populates="user")

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.username

    def __eq__(self, other):
        self.username == other.username

    def __json__(self):
        return {
            'username': self.username,
            'password': self.password,
            'is_authenticated': self.is_authenticated,
            'scenarios': self.scenarios,
            'certificates': self.certificates}