from sqlalchemy import Column, Integer, ForeignKey
from . import Base

class ProjectMembers(Base):
    __tablename__="projectmembers"
    project_id = Column(Integer, ForeignKey("projects.id"), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)