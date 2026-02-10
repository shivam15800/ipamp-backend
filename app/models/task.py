from sqlalchemy import Column, Integer, String, ForeignKey
from . import Base

class Task(Base):
    __tablename__="tasks"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    assigned_to = Column(Integer, ForeignKey("users.id"))
    title = Column(String(200), nullable=False)
    status = Column(String(50), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"))


