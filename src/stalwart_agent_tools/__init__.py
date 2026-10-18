"""Public versioned adapter API; credentials stay outside this package."""
from .adapter import StalwartAdapter, ProfilePolicy, PolicyError, BackendError
__version__ = "0.1.0"
__all__ = ["StalwartAdapter", "ProfilePolicy", "PolicyError", "BackendError"]
