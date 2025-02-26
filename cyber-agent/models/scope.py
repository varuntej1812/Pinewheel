from ipaddress import ip_network, ip_address
from typing import List
from pydantic import BaseModel

class ScopeDefinition(BaseModel):
    domains: List[str] = []
    ip_ranges: List[str] = []

class ScopeValidator:
    def __init__(self, scope: ScopeDefinition):
        self.domains = scope.domains
        self.ip_ranges = [ip_network(range) for range in scope.ip_ranges]
        
    def validate_target(self, target: str) -> bool:
        # Clean target input
        clean_target = target.split('//')[-1].split('/')[0].strip()
        
        try:  # Check IP ranges
            ip = ip_address(clean_target)
            return any(ip in network for network in self.ip_ranges)
        except ValueError:  # Check domains
            return any(
                domain == clean_target or 
                (domain.startswith('.') and clean_target.endswith(domain))
                for domain in self.domains
            )