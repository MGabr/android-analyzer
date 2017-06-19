import celery
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session


engine = create_engine('mysql+mysqldb://root:mypass@mysql/android-analyzer')

Base = declarative_base()

Session = scoped_session(sessionmaker(bind=engine, autocommit=False, autoflush=False))


class SQLAlchemyTask(celery.Task):
    abstract = True

    def after_return(self, status, retval, task_id, args, kwargs, einfo):
        Session.remove()
