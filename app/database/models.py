"""SQLAlchemy database models for Whaley."""
from datetime import datetime
from typing import Optional
from sqlalchemy import Column, Integer, String, Text, DateTime, Index, JSON
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class UserPortMapping(Base):
    """Persistent port allocation mapping for users/teams."""
    __tablename__ = "user_port_mappings"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(64), nullable=False, index=True)
    username = Column(String(255), nullable=True)
    challenge_id = Column(String(128), nullable=False, index=True)
    internal_port = Column(Integer, nullable=False)
    external_port = Column(Integer, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index('ix_user_challenge', 'user_id', 'challenge_id'),
    )
    
    def __repr__(self):
        return f"<UserPortMapping(user={self.user_id}, challenge={self.challenge_id}, {self.internal_port}->{self.external_port})>"


class EventLog(Base):
    """Event log entries for tracking system and user actions."""
    __tablename__ = "event_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    user_id = Column(String(64), nullable=True, index=True)
    username = Column(String(255), nullable=True)
    instance_id = Column(String(128), nullable=True, index=True)
    challenge_id = Column(String(128), nullable=True)
    ports_json = Column(Text, nullable=True)  # JSON serialized port mapping
    public_url = Column(String(512), nullable=True)
    message = Column(Text, nullable=False)
    details_json = Column(Text, nullable=True)  # JSON serialized details
    ip_address = Column(String(45), nullable=True)  # IPv6 max length
    
    __table_args__ = (
        Index('ix_event_user_type', 'user_id', 'event_type'),
        Index('ix_event_timestamp_type', 'timestamp', 'event_type'),
    )
    
    def __repr__(self):
        return f"<EventLog(id={self.id}, type={self.event_type}, user={self.username})>"


class InstanceState(Base):
    """Active instance state for recovery and tracking."""
    __tablename__ = "instance_states"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    instance_id = Column(String(128), unique=True, nullable=False, index=True)
    challenge_id = Column(String(128), nullable=False)
    user_id = Column(String(64), nullable=False, index=True)
    username = Column(String(255), nullable=True)
    team_id = Column(String(64), nullable=True, index=True)
    team_name = Column(String(255), nullable=True)
    owner_id = Column(String(64), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="starting")
    ports_json = Column(Text, nullable=True)  # JSON: {internal: external}
    public_urls_json = Column(Text, nullable=True)  # JSON: {internal: url}
    network_name = Column(String(128), nullable=True)
    container_ids_json = Column(Text, nullable=True)  # JSON: [container_ids]
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    error_message = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<InstanceState(id={self.instance_id}, status={self.status})>"
