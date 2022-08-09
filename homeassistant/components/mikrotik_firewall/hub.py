"""Mikrotik API encapsulation class."""


class MikrotikHub:
    """Placeholder class to make tests pass.

    TODO Remove this placeholder class and replace with things from your PyPI package.
    """

    def __init__(self, host: str) -> None:
        """Initialize."""
        self.host = host

    async def authenticate(self, username: str, password: str) -> bool:
        """Test if we can authenticate with the host."""
        return True

    async def get_rules(self, rules_filter: str = None) -> list[str]:
        """Get list of firewall rules from router."""
        return ["net_mati", "net_tv", "net_chrome"]

    async def fetch_data(self, rules_filter: str = None):
        """Get current rules states."""
        return {
            "net_mati": {"state": True},
            "net_tv": {"state": True},
            "net_chrome": {"state": True},
        }

    async def save_data(self):
        """Update rules states."""
