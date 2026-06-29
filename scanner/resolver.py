import dns.resolver

_resolver = dns.resolver.Resolver()
# Default to public DNS so checks work regardless of the container's network environment
_resolver.nameservers = ["1.1.1.1", "8.8.8.8"]


def configure(nameservers: list[str]) -> None:
    """Update the shared resolver with a new list of nameserver IPs."""
    valid = [s.strip() for s in nameservers if s.strip()]
    if valid:
        _resolver.nameservers = valid


def get() -> dns.resolver.Resolver:
    return _resolver
