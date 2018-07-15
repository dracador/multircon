class RCONError(Exception):
    """Base exception for all RCON-related errors."""


class RCONCommunicationError(RCONError):
    """Used for propagating socket-related errors."""


class RCONTimeoutError(RCONError):
    """Raised when a timeout occurs waiting for a response."""


class RCONAuthenticationError(RCONError):
    """Raised for failed authentication."""

    def __init__(self, banned=False):
        super(RCONError, self).__init__(
            "Banned" if banned else "Wrong password")
        self.banned = banned
