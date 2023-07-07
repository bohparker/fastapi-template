from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Table, Column, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship, WriteOnlyMapped

from .db_config import Model


# linking table for Role - Permission
RolePermission = Table(
    'roles_permissions',
    Model.metadata,
    Column('role_id', ForeignKey('roles.id'), primary_key=True, nullable=False),
    Column('permission_id', ForeignKey('permissions.id'), primary_key=True, nullable=False)
)


class Role(Model):
    __tablename__ = 'roles'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(32), index=True, unique=True)
    
    users: WriteOnlyMapped['User'] = relationship(
        back_populates='role'
    )
    
    permissions: Mapped[list['Permission']] = relationship(
        lazy='selectin', secondary=RolePermission, back_populates='roles'
    )
    

class Permission(Model):
    __tablename__ = 'permissions'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(32), index=True, unique=True)
    
    roles: Mapped[list['Role']] = relationship(
        lazy='selectin', secondary=RolePermission, back_populates='permissions'
    )
    
    
class User(Model):
    __tablename__ = 'users'
    
    id: Mapped[UUID] = mapped_column(default=uuid4, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), index=True, unique=True)
    password_hash: Mapped[str]
    role_id: Mapped[int] = mapped_column(ForeignKey('roles.id'), index=True)
    disabled: Mapped[bool] = mapped_column(index=True, default=False)
    
    role: Mapped['Role'] = relationship(
        lazy='joined', innerjoin=True, back_populates='users'
    )