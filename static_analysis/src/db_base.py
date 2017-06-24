import celery
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session

from common import config


engine = create_engine(config.MYSQL_URL)

Base = declarative_base()

Session = scoped_session(sessionmaker(bind=engine, autocommit=False, autoflush=False))


class SQLAlchemyTask(celery.Task):
    abstract = True

    def after_return(self, status, retval, task_id, args, kwargs, einfo):
        Session.flush()
        Session.remove()
