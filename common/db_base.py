# during docker build common is copied into each subproject

# Base in db_base should specify the Base class to use for sqlalchemy
# for flask this will be db.Model instead of a Base = declarative_base()
from src.db_base import Base