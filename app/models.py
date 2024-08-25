from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = 'Users'
    user_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    first_name = Column(String(50))
    last_name = Column(String(50))
    user_name = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    phone = Column(String(20))
    time_zone = Column(String(50))
    scope = Column(String(100))
    about_us = Column(Text)  # Add about_us field
    tenant_id = Column(Integer, ForeignKey('Tenants.tenant_id'))
    is_active = Column(Boolean, default=True)
    registration_token = Column(String(36), nullable=True)

    tenant = relationship('Tenant', back_populates='users')
    roles = relationship('UserRole', back_populates='user')

class Organization(Base):
    __tablename__ = 'Organizations'
    organization_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    tenant_id = Column(Integer, ForeignKey('Tenants.tenant_id'))
    legal_name = Column(String(100))
    address = Column(String(255))
    neighborhood = Column(String(100))
    city = Column(String(100))
    state = Column(String(100))
    country = Column(String(100))
    postal_code = Column(String(20))
    time_zone = Column(String(50))
    is_active = Column(Boolean, default=True)

    tenant = relationship('Tenant', back_populates='organizations')
    roles = relationship('UserRole', back_populates='organization')
    reviews = relationship('Review', back_populates='organization')


class Tenant(Base):
    __tablename__ = 'Tenants'
    tenant_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), unique=True)

    users = relationship('User', back_populates='tenant')
    organizations = relationship('Organization', back_populates='tenant')
    subscriptions = relationship('AppSubscription', back_populates='tenant')



class Role(Base):
    __tablename__ = 'Roles'
    role_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    role_name = Column(String(50))

    user_roles = relationship('UserRole', back_populates='role')

class UserRole(Base):
    __tablename__ = 'UserRoles'
    user_role_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('Users.user_id'))
    role_id = Column(Integer, ForeignKey('Roles.role_id'))
    organization_id = Column(Integer, ForeignKey('Organizations.organization_id'))

    user = relationship('User', back_populates='roles')
    role = relationship('Role', back_populates='user_roles')
    organization = relationship('Organization', back_populates='roles')

class App(Base):
    __tablename__ = 'Apps'
    app_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    app_name = Column(String(100))
    is_supported = Column(Boolean, default=True)

    reviews = relationship('Review', back_populates='app')
    subscriptions = relationship('AppSubscription', back_populates='app')

class Review(Base):
    __tablename__ = 'Reviews'
    review_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    app_id = Column(Integer, ForeignKey('Apps.app_id'))
    organization_id = Column(Integer, ForeignKey('Organizations.organization_id'))
    user_id = Column(Integer, ForeignKey('Users.user_id'))
    review_text = Column(Text)
    rating = Column(Integer)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    app = relationship('App', back_populates='reviews')
    organization = relationship('Organization', back_populates='reviews')
    user = relationship('User')

class AppSubscription(Base):
    __tablename__ = 'AppSubscriptions'
    subscription_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    tenant_id = Column(Integer, ForeignKey('Tenants.tenant_id'))
    app_id = Column(Integer, ForeignKey('Apps.app_id'))
    is_active = Column(Boolean, default=True)

    tenant = relationship('Tenant', back_populates='subscriptions')
    app = relationship('App', back_populates='subscriptions')
