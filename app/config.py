"""Configuration settings for the instancer."""
import os
import socket
import httpx
from typing import Optional
from pydantic_settings import BaseSettings


def get_public_ip() -> str:
    """Try to detect public IP address."""
    # Try external services first
    ip_services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
        "https://ipecho.net/plain",
    ]
    
    for service in ip_services:
        try:
            response = httpx.get(service, timeout=3.0)
            if response.status_code == 200:
                ip = response.text.strip()
                if ip:
                    return ip
        except Exception:
            continue
    
    # Fallback: try to get local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    
    # Final fallback
    return "localhost"


class Settings(BaseSettings):
    """Application settings."""
    
    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    
    # Instance settings
    INSTANCE_TIMEOUT: int = 3600  # 1 hour default timeout
    MAX_INSTANCES_PER_USER: int = 3
    MAX_INSTANCES_PER_TEAM: int = 5  # Team limit (typically higher than user)
    
    # Team mode settings
    # "auto" = detect from CTFd, "enabled" = force team mode, "disabled" = force user mode
    TEAM_MODE: str = "auto"
    
    # Port range for instances
    PORT_RANGE_START: int = 30000
    PORT_RANGE_END: int = 40000
    
    # Docker settings
    DOCKER_NETWORK: str = "ctf-instances"
    
    # Authentication settings
    AUTH_MODE: str = "ctfd"  # "ctfd" or "none"
    CTFD_URL: Optional[str] = None
    CTFD_API_KEY: Optional[str] = None  # Admin API key for validation
    
    # Dynamic flag settings
    DYNAMIC_FLAGS_ENABLED: bool = False  # Enable per-user dynamic flags
    FLAG_PREFIX: str = "FLAG"  # Prefix for generated flags
    
    # Admin dashboard settings
    ADMIN_KEY: Optional[str] = None  # Secret key for admin dashboard access
    
    # Rate limiting for admin endpoints (requests per minute)
    ADMIN_RATE_LIMIT: int = 150  # Max requests per minute per IP
    
    # Instance Forensics settings (Docker log capture)
    # Auto Capture: automatically dump logs when instance terminates
    FORENSICS_AUTO_CAPTURE: bool = False  # OFF by default (can be toggled via admin panel)
    # Log size limits
    FORENSICS_MAX_SIZE_MB: int = 5  # Max log size per instance (MB)
    FORENSICS_TAIL_LINES: int = 1000  # Max lines to capture per container
    # Retention
    FORENSICS_RETENTION_HOURS: int = 168  # Auto-delete logs older than this (168 = 7 days)
    # Compression
    FORENSICS_COMPRESSION: bool = True  # Compress logs with gzip
    # Storage path
    FORENSICS_LOG_DIR: str = "/app/logs/forensics"
    
    # Trusted proxies for X-Forwarded-For header
    # Only trust these IPs to set forwarded headers (prevents IP spoofing)
    # Use comma-separated values, e.g., "127.0.0.1,10.0.0.1" or "*" to trust all (not recommended)
    TRUSTED_PROXIES: str = "127.0.0.1,::1"
    
    # Challenge configs directory
    CHALLENGES_DIR: str = "/challenges"
    
    # Database settings (SQLite by default, can use PostgreSQL)
    DATABASE_URL: Optional[str] = None  # e.g., sqlite+aiosqlite:///./data/whaley.db
    DATA_DIR: str = "/app/data"  # Directory for SQLite database
    
    # Redis for distributed locking and state management
    REDIS_URL: Optional[str] = None  # e.g., redis://localhost:6379/0
    
    # Network isolation settings
    NETWORK_ISOLATION_ENABLED: bool = True  # Create isolated network per instance
    NETWORK_ICC_DISABLED: bool = True  # Disable inter-container communication
    NETWORK_PREFIX: str = "whaley"  # Prefix for instance networks
    
    # Public URL for instance access (auto-detect if "auto" or empty)
    PUBLIC_HOST: str = "auto"
    
    # Logging
    LOG_FILE: str = "/app/logs/events.jsonl"
    USER_PORTS_FILE: str = "/app/logs/user_ports.json"
    
    def get_public_host(self) -> str:
        """Get the public host, auto-detecting if needed."""
        if self.PUBLIC_HOST and self.PUBLIC_HOST.lower() not in ("auto", ""):
            return self.PUBLIC_HOST
        return get_public_ip()
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
