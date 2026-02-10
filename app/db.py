# from .extensions import db
from sqlalchemy import create_engine
from models import Base

engine = create_engine("mysql+pymysql://shivam:12345@localhost:3306/ipamp_backend")

Base.metadata.create_all(engine)

print("Tables created successfully!")