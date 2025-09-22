from sqlalchemy.orm import declarative_base

from app.models.access_request import AccessRequest  # noqa: F401
from app.models.audit import AuditEvent  # noqa: F401
from app.models.server import Server  # noqa: F401
from app.models.sshkey import SSHKey  # noqa: F401
from app.models.user import User  # noqa: F401

Base = declarative_base()