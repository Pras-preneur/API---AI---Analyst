import copy
from typing import Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import JSONResponse

# In‑memory data store (mutable, will be reset by the /reset endpoint)
_INITIAL_USERS = {
    "user_a": {
        "username": "user_a",
        "full_name": "User A",
        "role": "user",
        "email": "a@example.com",
        "profile": {"bio": "I am User A", "age": 30},
    },
    "user_b": {
        "username": "user_b",
        "full_name": "User B",
        "role": "user",
        "email": "b@example.com",
        "profile": {"bio": "I am User B", "age": 25},
    },
    "admin": {
        "username": "admin",
        "full_name": "Administrator",
        "role": "admin",
        "email": "admin@example.com",
        "profile": {"bio": "Admin account", "age": 40},
    },
}

# Deep copy to avoid shared mutable defaults
users_store: Dict[str, Dict[str, Any]] = copy.deepcopy(_INITIAL_USERS)

security = HTTPBasic()

def get_current_user(credentials: HTTPBasicCredentials = Depends(security)) -> Dict[str, Any]:
    """Simple HTTP‑Basic authentication against the in‑memory users.

    Dummy credentials (do **not** use real passwords):
    * user_a / passwordA
    * user_b / passwordB
    * admin / adminPass
    """
    username = credentials.username
    password = credentials.password
    # Hard‑coded dummy passwords (never store real secrets)
    dummy_passwords = {
        "user_a": "passwordA",
        "user_b": "passwordB",
        "admin": "adminPass",
    }
    if username not in dummy_passwords or dummy_passwords[username] != password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    user = users_store.get(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


def is_admin(user: Dict[str, Any]) -> bool:
    return user.get("role") == "admin"


mock_app = FastAPI(title="API Security Testing Assistant – Mock API", openapi_url="/mock/openapi.json")

# ---------------------------------------------------------------------------
# Public endpoints (no auth)
# ---------------------------------------------------------------------------
@mock_app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}

# Deliberately vulnerable endpoint exposing *all* users without auth
@mock_app.get("/vuln/expose-all")
async def expose_all_users() -> Dict[str, Any]:
    """Vulnerable: excessive data exposure – returns every user record.
    Intended for educational testing only.
    """
    return {"users": list(users_store.values())}

# ---------------------------------------------------------------------------
# Authenticated user endpoints
# ---------------------------------------------------------------------------
@mock_app.get("/profile")
async def get_profile(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    return {"username": current_user["username"], "profile": current_user["profile"]}

@mock_app.patch("/profile")
async def update_profile(payload: Dict[str, Any], current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Mass‑assignment‑vulnerable update: any keys in the payload are merged
    directly into the user's profile without validation.
    """
    # Vulnerable behaviour – blindly update
    current_user["profile"].update(payload)
    return {"msg": "profile updated", "profile": current_user["profile"]}

# ---------------------------------------------------------------------------
# Object‑level endpoint (potential BOLA)
# ---------------------------------------------------------------------------
@mock_app.get("/users/{username}")
async def get_user_object(username: str, request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Secure version: only the owner can fetch their object.
    Vulnerable version is provided under the `/vuln` prefix.
    """
    if username != current_user["username"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    user = users_store.get(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

# Vulnerable BOLA – no ownership check
@mock_app.get("/vuln/users/{username}")
async def vulnerable_get_user(username: str) -> Dict[str, Any]:
    user = users_store.get(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

# ---------------------------------------------------------------------------
# Administrator‑only endpoint (potential BFLA)
# ---------------------------------------------------------------------------
@mock_app.get("/admin/data")
async def admin_data(current_user: Dict[str, Any] = Depends(get_current_user)):
    if not is_admin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    return {"secret": "admin‑only data", "admin_data": "administrative_confidential_report"}

# Vulnerable admin endpoint – accessible to any authenticated user
@mock_app.get("/vuln/admin/data")
async def vulnerable_admin_data(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {"secret": "admin‑only data (insecure)", "admin_data": "administrative_confidential_report"}

# ---------------------------------------------------------------------------
# Broken Authentication Testing Endpoints (Stage 6.3.4 Demonstration)
# ---------------------------------------------------------------------------
@mock_app.get("/auth/secure/profile")
async def secure_profile(request: Request) -> Dict[str, Any]:
    """Scenario A: Secure endpoint requiring valid authentication.

    Returns HTTP 401 Unauthorized when credentials are missing or empty.
    Returns protected user profile data for authenticated requests.
    """
    auth = request.headers.get("Authorization")
    if not auth or not auth.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if auth.startswith("Bearer "):
        token = auth.split("Bearer ", 1)[1].strip()
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    elif auth.startswith("Basic "):
        pass
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unsupported authentication scheme",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "user_id": "usr_alice",
        "username": "alice",
        "email": "alice@example.com",
        "role": "user",
        "account_status": "active",
        "profile_data": "confidential_user_profile_data",
    }


@mock_app.get("/auth/vulnerable/profile")
async def vulnerable_profile(request: Request) -> Dict[str, Any]:
    """Scenario B: Deliberately vulnerable endpoint for local security testing.

    OpenAPI declares that authentication is required (BearerAuth), but the endpoint
    fails to verify credentials and returns protected profile data even to unauthenticated requests.
    """
    return {
        "user_id": "usr_alice",
        "username": "alice",
        "email": "alice@example.com",
        "role": "user",
        "account_status": "active",
        "profile_data": "confidential_user_profile_data",
        "fixture_note": "Local mock test fixture: vulnerable missing-credentials endpoint",
    }

# ---------------------------------------------------------------------------
# Reset endpoint – only available when called from localhost in mock‑test mode
# ---------------------------------------------------------------------------
@mock_app.post("/reset")
async def reset_store(request: Request):
    client_host = request.client.host if request.client else ""
    if client_host not in ("127.0.0.1", "::1", "testclient"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Reset only allowed from localhost")
    # Reset the in‑memory store to its initial fixture state
    global users_store
    users_store = copy.deepcopy(_INITIAL_USERS)
    return JSONResponse(content={"msg": "store reset"})

# ---------------------------------------------------------------------------
# Entry point for running the mock API directly
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.mock_api:mock_app", host="127.0.0.1", port=8001, reload=False)
