"""IP exclusion parsing and matching."""

import ipaddress
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple, Union


@dataclass(frozen=True)
class IPExclusions:
    """CIDR-aware IP exclusion list."""
    networks: Tuple[Union[ipaddress.IPv4Network, ipaddress.IPv6Network], ...]

    @classmethod
    def from_values(
        cls,
        values: Optional[Iterable[str]] = None,
        option_name: str = "--exclude-ip",
    ) -> "IPExclusions":
        networks = []
        for value in values or []:
            for part in value.split(','):
                item = part.strip()
                if not item:
                    continue
                try:
                    networks.append(ipaddress.ip_network(item, strict=False))
                except ValueError as e:
                    raise ValueError(f"Invalid {option_name} value '{item}': {e}") from e
        return cls(tuple(networks))

    def __bool__(self) -> bool:
        return bool(self.networks)

    def contains_ip(self, ip: str) -> bool:
        if not self.networks:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in network for network in self.networks)

    def summary(self) -> str:
        return ', '.join(str(network) for network in self.networks)
