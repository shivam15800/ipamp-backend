from sqlalchemy import Column, Integer, String, ForeignKey
from . import Base

class Project(Base):
    __tablename__="projects"
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    description = Column(String(500))
    owner_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(String(50))


