"""Public versioned adapter API; credentials remain environment references."""
from .core import (
    AmbiguousSubmission, CalendarBinding, CalDAVBridgeTarget, ConflictError, IdempotencyStore,
    PolicyError, ProfilePolicy, StalwartAdapter, StalwartTransport,
    TransportError, invitation_ics, resolve_policy, validate_bridge_url,
)
from .bridge import OwnershipManifest, PinnedHTTPSClient, refresh as refresh_external_ics
__version__ = "0.2.0"
__all__ = ["AmbiguousSubmission", "CalendarBinding", "CalDAVBridgeTarget", "ConflictError", "IdempotencyStore", "PolicyError", "ProfilePolicy", "StalwartAdapter", "StalwartTransport", "TransportError", "OwnershipManifest", "PinnedHTTPSClient", "refresh_external_ics", "invitation_ics", "resolve_policy", "validate_bridge_url"]
