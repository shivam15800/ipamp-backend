from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

#Import all models to register with Base
from .user import User
from .project import Project
from .projectMembers import ProjectMembers
from .task import Task
from .document import Document