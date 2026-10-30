"""Configuration constants for API Security Assistant."""

# Maximum allowed size for an OpenAPI specification file (bytes)
MAX_SPEC_SIZE = 5 * 1024 * 1024  # 5 MB

# Supported HTTP methods for parsing
SUPPORTED_METHODS = [
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
]

# Authorized targets for execution (strictly local mock API only)
ALLOWED_TARGETS = {"http://127.0.0.1:8001", "http://localhost:8001"}

# Global execution safety limits
MAX_REQUESTS_PER_EXECUTION = 10
DEFAULT_REQUEST_TIMEOUT = 5.0  # seconds
