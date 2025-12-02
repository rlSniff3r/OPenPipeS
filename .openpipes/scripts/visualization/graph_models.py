"""
Data models for attack surface graph
NetworkX-compatible node and edge definitions
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from datetime import datetime
import networkx as nx


class NodeType(Enum):
    """Types of nodes in the attack surface graph"""
    SLD = "sld"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    ASN = "asn"
    ISP = "isp"
    SERVICE = "service"
    DOMAIN_LEVEL = "domain_level"


class EdgeType(Enum):
    """Types of relationships between nodes"""
    RESOLVES_TO = "resolves_to"
    BELONGS_TO = "belongs_to"
    HOSTS = "hosts"
    HAS_VULN = "has_vulnerability"
    REVERSE_DNS = "reverse_dns"
    CDN_FRONTS = "cdn_fronts"
    SAME_NETBLOCK = "same_netblock"


@dataclass
class Node:
    """Represents a node in the attack surface graph"""
    id: str
    type: NodeType
    label: str
    
    # IP metadata
    ip_version: Optional[str] = None  # "v4" or "v6"
    asn: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None
    
    # Discovery data
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)  # {port: "service/version"}
    technologies: List[str] = field(default_factory=list)
    
    # Status
    is_active: bool = True
    is_cdn: bool = False
    is_shared_hosting: bool = False
    
    # Criticality
    criticality_score: float = 0.0  # 0-1
    max_cvss_associated: float = 0.0
    vulnerability_count: int = 0
    
    # Timestamps
    discovered_at: str = ""
    last_updated: str = ""
    
    # Audit
    source: str = ""  # "recon", "nmap", "httpx", "nuclei", "whois"
    confidence: float = 1.0  # 0-1
    
    def __hash__(self):
        return hash(self.id)
    
    def to_dict(self) -> Dict:
        """Convert to dict for serialization"""
        return {
            'id': self.id,
            'type': self.type.value,
            'label': self.label,
            'ip_version': self.ip_version,
            'asn': self.asn,
            'isp': self.isp,
            'country': self.country,
            'open_ports': self.open_ports,
            'services': self.services,
            'technologies': self.technologies,
            'is_active': self.is_active,
            'is_cdn': self.is_cdn,
            'is_shared_hosting': self.is_shared_hosting,
            'criticality_score': self.criticality_score,
            'max_cvss_associated': self.max_cvss_associated,
            'vulnerability_count': self.vulnerability_count,
            'discovered_at': self.discovered_at,
            'source': self.source,
            'confidence': self.confidence
        }


@dataclass
class Edge:
    """Represents a relationship between nodes"""
    source_id: str
    target_id: str
    relation_type: EdgeType
    
    metadata: Dict = field(default_factory=dict)
    discovered_at: str = ""
    source_module: str = ""  # "recon", "nmap", "httpx", "nuclei", "whois"
    
    def to_dict(self) -> Dict:
        """Convert to dict for serialization"""
        return {
            'source': self.source_id,
            'target': self.target_id,
            'type': self.relation_type.value,
            'metadata': self.metadata,
            'discovered_at': self.discovered_at,
            'source_module': self.source_module
        }


class AttackSurfaceGraph:
    """Main graph data structure for attack surface"""
    
    def __init__(self, target_sld: str):
        self.target_sld = target_sld
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self.created_at = datetime.now().isoformat()
    
    def add_node(self, node: Node) -> None:
        """Add node to graph"""
        self.nodes[node.id] = node
    
    def add_edge(self, edge: Edge) -> None:
        """Add edge to graph"""
        self.edges.append(edge)
    
    def get_node(self, node_id: str) -> Optional[Node]:
        """Get node by ID"""
        return self.nodes.get(node_id)
    
    def get_edges_from(self, node_id: str) -> List[Edge]:
        """Get all edges originating from node"""
        return [e for e in self.edges if e.source_id == node_id]
    
    def get_edges_to(self, node_id: str) -> List[Edge]:
        """Get all edges targeting node"""
        return [e for e in self.edges if e.target_id == node_id]
    
    def to_networkx(self) -> nx.DiGraph:
        """Convert to NetworkX DiGraph for analysis"""
        G = nx.DiGraph()
        
        # Add nodes
        for node_id, node in self.nodes.items():
            G.add_node(
                node_id,
                type=node.type.value,
                label=node.label,
                criticality=node.criticality_score,
                is_cdn=node.is_cdn,
                is_active=node.is_active,
                services=len(node.open_ports)
            )
        
        # Add edges
        for edge in self.edges:
            G.add_edge(
                edge.source_id,
                edge.target_id,
                relation=edge.relation_type.value,
                metadata=edge.metadata
            )
        
        return G
    
    def get_stats(self) -> Dict:
        """Return graph statistics"""
        return {
            'target': self.target_sld,
            'total_nodes': len(self.nodes),
            'total_edges': len(self.edges),
            'subdomains': len([n for n in self.nodes.values() if n.type == NodeType.SUBDOMAIN]),
            'ips': len([n for n in self.nodes.values() if n.type == NodeType.IP]),
            'asns': len([n for n in self.nodes.values() if n.type == NodeType.ASN]),
            'services': len([n for n in self.nodes.values() if n.type == NodeType.SERVICE]),
            'vulnerabilities': len([e for e in self.edges if e.relation_type == EdgeType.HAS_VULN]),
            'created_at': self.created_at
        }