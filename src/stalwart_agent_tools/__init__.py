"""Public versioned adapter API; credentials remain environment references."""
from .core import (
    AmbiguousSubmission, CalendarBinding, ConflictError, IdempotencyStore,
    PolicyError, ProfilePolicy, StalwartAdapter, StalwartTransport,
    TransportError, invitation_ics, resolve_policy, validate_bridge_url,
)
__version__ = "0.2.0"
__all__ = ["AmbiguousSubmission", "CalendarBinding", "ConflictError", "IdempotencyStore", "PolicyError", "ProfilePolicy", "StalwartAdapter", "StalwartTransport", "TransportError", "invitation_ics", "resolve_policy", "validate_bridge_url"]
