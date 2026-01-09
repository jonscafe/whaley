"""Authentication handlers for CTFd and no-auth modes."""
import httpx
from typing import Optional, Tuple
from fastapi import HTTPException, Header, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .config import settings
from .models import UserInfo, AuthMode


security = HTTPBearer(auto_error=False)


class CTFdAuth:
    """CTFd authentication handler."""
    
    def __init__(self, ctfd_url: str, api_key: Optional[str] = None):
        self.ctfd_url = ctfd_url.rstrip('/')
        self.api_key = api_key
        self._ctfd_mode_cache: Optional[str] = None  # Cache for CTFd mode (users/teams)
    
    async def get_ctfd_mode(self) -> str:
        """
        Check if CTFd is in 'users' or 'teams' mode.
        Returns 'users' or 'teams'. Caches the result.
        """
        if self._ctfd_mode_cache:
            return self._ctfd_mode_cache
        
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
                team_id = user_data.get("team_id")
                team_name = None
                
                # Fetch team name if user has team_id
                if team_id:
                    team_info = await self.get_team_info(team_id, token)
                    if team_info:
                        team_name = team_info.get("name")
                
                return UserInfo(
                    user_id=str(user_data.get("id")),
                    username=user_data.get("name", "unknown"),
                    team_id=str(team_id) if team_id else None,
                    team_name=team_name
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
ctfd_auth: Optional[CTFdAuth] = None
no_auth = NoAuth()

# Team mode state
_team_mode_enabled: Optional[bool] = None


def init_auth():
    """Initialize authentication based on settings."""
    global ctfd_auth
    if settings.AUTH_MODE == AuthMode.CTFD and settings.CTFD_URL:
        ctfd_auth = CTFdAuth(settings.CTFD_URL, settings.CTFD_API_KEY)


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


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_forwarded_for: Optional[str] = Header(None),
    x_real_ip: Optional[str] = Header(None),
) -> UserInfo:
    """Get the current authenticated user."""
    
    if settings.AUTH_MODE == AuthMode.NONE:
        # Use IP-based identification
        identifier = x_forwarded_for or x_real_ip or "anonymous"
        # Use first IP if multiple
        if "," in identifier:
            identifier = identifier.split(",")[0].strip()
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
