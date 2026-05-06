"""Authentication handlers for CTFd and no-auth modes."""
import ipaddress
import httpx
from typing import Optional
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .config import settings
from .models import UserInfo, AuthMode


security = HTTPBearer(auto_error=False)


class CTFdAuth:
    """CTFd authentication handler."""
    
    def __init__(self):
        self._ctfd_mode_cache: Optional[str] = None  # Cache for CTFd mode (users/teams)

    @property
    def ctfd_url(self) -> str:
        return (settings.CTFD_URL or "").rstrip('/')

    @property
    def api_key(self) -> str:
        return settings.CTFD_API_KEY or ""

    def clear_cache(self) -> None:
        """Clear cached CTFd metadata after settings change."""
        self._ctfd_mode_cache = None
    
    async def get_ctfd_mode(self) -> str:
        """
        Check if CTFd is in 'users' or 'teams' mode.
        Returns 'users' or 'teams'. Caches the result.
        """
        if self._ctfd_mode_cache:
            return self._ctfd_mode_cache

        if not self.ctfd_url or not self.api_key:
            return "users"
        
        try:
            async with httpx.AsyncClient() as client:
                # Try getting user_mode config from CTFd
                response = await client.get(
                    f"{self.ctfd_url}/api/v1/configs/user_mode",
                    headers={
                        "Authorization": f"Token {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("success"):
                        mode = data.get("data", {}).get("value", "users")
                        self._ctfd_mode_cache = mode
                        print(f"CTFd mode detected: {mode}")
                        return mode
                
                # Fallback: check if teams endpoint works
                teams_response = await client.get(
                    f"{self.ctfd_url}/api/v1/teams",
                    headers={
                        "Authorization": f"Token {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    params={"per_page": 1},
                    timeout=10.0
                )
                
                if teams_response.status_code == 200:
                    teams_data = teams_response.json()
                    if teams_data.get("success") and teams_data.get("data"):
                        self._ctfd_mode_cache = "teams"
                        print("CTFd mode detected from teams endpoint: teams")
                        return "teams"
                
        except Exception as e:
            print(f"Error detecting CTFd mode: {e}")
        
        # Default to users mode
        self._ctfd_mode_cache = "users"
        return "users"
    
    async def get_team_info(self, team_id: int, token: str) -> Optional[dict]:
        """Fetch team info from CTFd API."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.ctfd_url}/api/v1/teams/{team_id}",
                    headers={
                        "Authorization": f"Token {token}",
                        "Content-Type": "application/json"
                    },
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("success"):
                        return data.get("data", {})
        except Exception as e:
            print(f"Error fetching team info: {e}")
        
        return None
    
    async def get_team_members(self, team_id: int, token: str) -> list:
        """Fetch team members from CTFd API."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.ctfd_url}/api/v1/teams/{team_id}/members",
                    headers={
                        "Authorization": f"Token {token}",
                        "Content-Type": "application/json"
                    },
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("success"):
                        return data.get("data", [])
        except Exception as e:
            print(f"Error fetching team members: {e}")
        
        return []
    
    async def validate_token(self, token: str) -> Optional[UserInfo]:
        """Validate a CTFd access token and get user info."""
        if not self.ctfd_url:
            print("CTFd auth failed: CTFD_URL is not configured")
            return None

        try:
            async with httpx.AsyncClient() as client:
                # CTFd uses "Token <access_token>" format, not "Bearer"
                headers = {
                    "Authorization": f"Token {token}",
                    "Content-Type": "application/json"
                }
                
                # Get current user info
                response = await client.get(
                    f"{self.ctfd_url}/api/v1/users/me",
                    headers=headers,
                    timeout=10.0
                )

                if response.status_code != 200:
                    print(f"CTFd auth failed: status={response.status_code}, body={response.text}")
                    return None
                
                data = response.json()
                if not data.get("success"):
                    print(f"CTFd auth failed: response={data}")
                    return None
                
                user_data = data.get("data", {})
                user_id = user_data.get("id")
                if not user_id:
                    print(f"CTFd auth failed: missing user id in response={data}")
                    return None

                # CTFd's /users/me response may omit role/type on some setups.
                # Fetch the detailed user record and use its "type" field for RBAC.
                detail_response = await client.get(
                    f"{self.ctfd_url}/api/v1/users/{user_id}",
                    headers=headers,
                    timeout=10.0
                )
                if detail_response.status_code == 200:
                    detail_data = detail_response.json()
                    if detail_data.get("success"):
                        user_data = {
                            **user_data,
                            **(detail_data.get("data") or {})
                        }
                else:
                    print(
                        f"CTFd user detail lookup failed: user_id={user_id}, "
                        f"status={detail_response.status_code}, body={detail_response.text}"
                    )

                team_id = user_data.get("team_id")
                team_name = None
                user_type = user_data.get("type")
                
                # Fetch team name if user has team_id
                if team_id:
                    team_info = await self.get_team_info(team_id, token)
                    if team_info:
                        team_name = team_info.get("name")
                
                return UserInfo(
                    user_id=str(user_data.get("id")),
                    username=user_data.get("name", "unknown"),
                    team_id=str(team_id) if team_id else None,
                    team_name=team_name,
                    user_type=user_type,
                    is_admin=user_type == "admin"
                )
                
        except Exception as e:
            print(f"CTFd auth error: {e}")
            return None


class NoAuth:
    """No authentication handler - uses session/IP based identification."""
    
    async def get_user(self, identifier: str) -> UserInfo:
        """Generate a user based on identifier (IP or session)."""
        return UserInfo(
            user_id=identifier,
            username=f"user_{identifier[:8]}"
        )


# Global auth instances
ctfd_auth: CTFdAuth = CTFdAuth()
no_auth = NoAuth()

# Team mode state
_team_mode_enabled: Optional[bool] = None


def init_auth():
    """Initialize authentication based on settings."""
    # CTFdAuth is now always initialized and reads from settings dynamically
    pass


async def init_team_mode() -> bool:
    """
    Initialize team mode based on settings and CTFd configuration.
    Call this at application startup.
    Returns True if team mode is enabled.
    """
    global _team_mode_enabled
    
    if settings.TEAM_MODE == "enabled":
        _team_mode_enabled = True
        return True
    elif settings.TEAM_MODE == "disabled":
        _team_mode_enabled = False
        return False
    else:  # "auto" - detect from CTFd
        if settings.AUTH_MODE == AuthMode.CTFD and ctfd_auth:
            ctfd_mode = await ctfd_auth.get_ctfd_mode()
            _team_mode_enabled = (ctfd_mode == "teams")
            return _team_mode_enabled
        else:
            # No CTFd, default to user mode
            _team_mode_enabled = False
            return False


def is_team_mode() -> bool:
    """
    Check if team mode is enabled.
    Returns False if not yet initialized.
    """
    return _team_mode_enabled or False


def get_team_mode_status() -> Optional[bool]:
    """
    Get team mode status.
    Returns None if not yet initialized.
    """
    return _team_mode_enabled


def _get_trusted_proxies() -> set:
    """Parse trusted proxies from settings."""
    if settings.TRUSTED_PROXIES == "*":
        return {"*"}
    return set(p.strip() for p in settings.TRUSTED_PROXIES.split(",") if p.strip())


def get_authenticated_client_ip(request: Request) -> str:
    """
    Extract a client IP with trusted proxy validation.
    This is used by no-auth mode, where the IP is the user identity.
    """
    direct_ip = request.client.host if request.client else "unknown"
    trusted_proxies = _get_trusted_proxies()

    is_trusted = False
    if "*" in trusted_proxies:
        is_trusted = True
    elif direct_ip != "unknown":
        try:
            direct_addr = ipaddress.ip_address(direct_ip)
            for proxy in trusted_proxies:
                try:
                    if "/" in proxy:
                        if direct_addr in ipaddress.ip_network(proxy, strict=False):
                            is_trusted = True
                            break
                    elif direct_addr == ipaddress.ip_address(proxy):
                        is_trusted = True
                        break
                except ValueError:
                    continue
        except ValueError:
            pass

    if is_trusted:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

    return direct_ip


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> UserInfo:
    """Get the current authenticated user."""
    
    if settings.AUTH_MODE == AuthMode.NONE:
        # Use IP-based identification, but only trust proxy headers from trusted proxies.
        identifier = get_authenticated_client_ip(request) or "anonymous"
        return await no_auth.get_user(identifier)
    
    elif settings.AUTH_MODE == AuthMode.CTFD:
        # CTFd mode requires valid authentication - no fallback to anonymous
        if not credentials:
            raise HTTPException(
                status_code=401,
                detail="Authentication required. Provide CTFd access token using 'Authorization: Bearer <token>' header.",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        if not ctfd_auth:
            raise HTTPException(
                status_code=500,
                detail="CTFd authentication not configured. Check CTFD_URL setting."
            )
        
        user = await ctfd_auth.validate_token(credentials.credentials)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired CTFd access token. Please check your token and try again.",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        return user
    
    # Unknown auth mode - reject
    raise HTTPException(
        status_code=500, 
        detail=f"Unknown authentication mode: {settings.AUTH_MODE}"
    )
