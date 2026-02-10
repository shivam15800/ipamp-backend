from sqlalchemy import Column, Integer, String, ForeignKey
from . import Base

class Document(Base):
    __tablename__="documents"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    filename = Column(String(200), nullable=False)
    filepath = Column(String(500),nullable=False)
    uploaded_by = Column(Integer, ForeignKey("users.id"))
    uploaded_at = Column(String(50))
    mime_type = Column(String(100))
