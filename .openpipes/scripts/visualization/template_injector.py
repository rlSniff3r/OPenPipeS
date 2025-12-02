"""
Inject Mermaid visualizations into Obsidian markdown templates
Extra care taken for markdown/backtick nesting safety
"""

import logging
from pathlib import Path
from datetime import datetime
from .graph_models import NodeType, EdgeType, AttackSurfaceGraph
from .mermaid_generator import MermaidGenerator

logger = logging.getLogger(__name__)


class TemplateInjector:
    """Inject visualizations into markdown templates"""
    
    def __init__(self, graph: AttackSurfaceGraph, vault_dir: Path):
        self.graph = graph
        self.vault_dir = Path(vault_dir)
        self.generator = MermaidGenerator(graph)
    
    def inject_all(self) -> bool:
        """Inject all visualizations"""
        try:
            self._inject_attack_surface()
            self._inject_redundancy()
            self._inject_virtual_hosting()
            self._inject_asn_clustering()
            logger.info("✓ All visualizations injected")
            return True
        except Exception as e:
            logger.error(f"Error injecting visualizations: {e}")
            return False
    
    def _inject_attack_surface(self) -> None:
        """Inject Attack Surface Map into dashboard"""
        target_file = self._get_dashboard_path()
        section_content = self._build_attack_surface_section()
        self._append_section(target_file, section_content)
    
    def _inject_redundancy(self) -> None:
        """Inject Subdomain Redundancy Map"""
        target_file = self._get_dashboard_path()
        mermaid_code = self.generator.generate_subdomain_redundancy()
        section_content = self._build_redundancy_section(mermaid_code)
        self._append_section(target_file, section_content)
    
    def _inject_virtual_hosting(self) -> None:
        """Inject Virtual Hosting Map"""
        target_file = self._get_dashboard_path()
        mermaid_code = self.generator.generate_virtual_hosting()
        section_content = self._build_virtual_hosting_section(mermaid_code)
        self._append_section(target_file, section_content)
    
    def _inject_asn_clustering(self) -> None:
        """Inject ASN Clustering Map"""
        target_file = self._get_dashboard_path()
        mermaid_code = self.generator.generate_asn_clustering()
        section_content = self._build_asn_section(mermaid_code)
        self._append_section(target_file, section_content)
    
    def _build_attack_surface_section(self) -> str:
        """Build complete attack surface section"""
        mermaid_code = self.generator.generate_attack_surface()
        stats = self.graph.get_stats()
        
        critical_count = len([
            n for n in self.graph.nodes.values()
            if n.type == NodeType.IP and n.criticality_score > 0.7
        ])
        
        medium_count = len([
            n for n in self.graph.nodes.values()
            if n.type == NodeType.IP and 0.4 < n.criticality_score <= 0.7
        ])
        
        low_count = len([
            n for n in self.graph.nodes.values()
            if n.type == NodeType.IP and n.criticality_score <= 0.4
        ])
        
        cdn_count = len([
            n for n in self.graph.nodes.values()
            if n.is_cdn
        ])
        
        shared_hosting_count = len([
            n for n in self.graph.nodes.values()
            if n.is_shared_hosting
        ])
        
        # Build section line by line to avoid markdown conflicts
        lines = []
        lines.append("")
        lines.append("## 🎯 Attack Surface Map")
        lines.append("")
        lines.append("Complete topology of discovered infrastructure.")
        lines.append("")
        lines.append("```mermaid")
        lines.append(mermaid_code)
        lines.append("```")
        lines.append("")
        lines.append("### 📊 Statistics")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| **Subdomains** | {stats['subdomains']} |")
        lines.append(f"| **Unique IPs** | {stats['ips']} |")
        lines.append(f"| **ASNs** | {stats['asns']} |")
        lines.append(f"| **Open Services** | {stats['services']} |")
        lines.append(f"| **Vulnerabilities** | {stats['vulnerabilities']} |")
        lines.append("")
        lines.append("### 🔴 Criticality Breakdown")
        lines.append("")
        lines.append("| Level | Count | Score Range |")
        lines.append("|-------|-------|-------------|")
        lines.append(f"| **Critical** 🔴 | {critical_count} | > 0.7 |")
        lines.append(f"| **Medium** 🟡 | {medium_count} | 0.4 - 0.7 |")
        lines.append(f"| **Low** 🟢 | {low_count} | < 0.4 |")
        lines.append("")
        lines.append("### 🔎 Infrastructure Insights")
        lines.append("")
        lines.append(f"- **CDN Services**: {cdn_count} (Cloudflare, Akamai, Fastly detected)")
        lines.append(f"- **Shared Hosting**: {shared_hosting_count} IPs hosting multiple subdomains")
        lines.append(f"- **Attack Surface Density**: {len(self.graph.edges)} relationships mapped")
        lines.append("")
        lines.append("### ⚠️ Key Findings")
        lines.append("")
        lines.append(f"- **Entry Points**: {stats['subdomains']} unique subdomains for initial access")
        lines.append(f"- **Backend Servers**: {stats['ips']} IPs needing security assessment")
        lines.append(f"- **Service Diversity**: {stats['services']} different services across infrastructure")
        lines.append("")
        
        return "\n".join(lines)
    
    def _build_redundancy_section(self, mermaid_code: str) -> str:
        """Build redundancy section with safe markdown"""
        lines = []
        lines.append("")
        lines.append("## 🔄 Subdomain Redundancy Map")
        lines.append("")
        lines.append("Identifies subdomains with multiple IPs (HA/load balancing setup).")
        lines.append("")
        lines.append("```mermaid")
        lines.append(mermaid_code)
        lines.append("```")
        lines.append("")
        lines.append("### Analysis")
        lines.append("")
        lines.append("- Subdomains with >1 IP likely use load balancing or geographic distribution")
        lines.append("- Red = Likely HA setup, multiple points of entry")
        lines.append("- Green = Backup/failover configuration")
        lines.append("")
        
        return "\n".join(lines)
    
    def _build_virtual_hosting_section(self, mermaid_code: str) -> str:
        """Build virtual hosting section with safe markdown"""
        lines = []
        lines.append("")
        lines.append("## 🏢 Virtual Hosting Detection")
        lines.append("")
        lines.append("IPs sharing multiple subdomains (shared hosting indicator).")
        lines.append("")
        lines.append("```mermaid")
        lines.append(mermaid_code)
        lines.append("```")
        lines.append("")
        lines.append("### Risk Assessment")
        lines.append("")
        lines.append("- IPs hosting >3 subdomains suggest shared hosting")
        lines.append("- **Implication**: Lower control over infrastructure, potential for lateral movement")
        lines.append("- **Opportunity**: If compromised, multiple domains affected simultaneously")
        lines.append("")
        
        return "\n".join(lines)
    
    def _build_asn_section(self, mermaid_code: str) -> str:
        """Build ASN clustering section with safe markdown"""
        lines = []
        lines.append("")
        lines.append("## 🌐 Infrastructure Distribution by ASN")
        lines.append("")
        lines.append("Shows clustering of IPs by Autonomous System Number (ISP ownership).")
        lines.append("")
        lines.append("```mermaid")
        lines.append(mermaid_code)
        lines.append("```")
        lines.append("")
        lines.append("### Strategic Insights")
        lines.append("")
        lines.append("- Single ASN = SPOF (Single Point of Failure), infrastructure concentration risk")
        lines.append("- Multiple ASNs = Distributed infrastructure, resilience against regional outages")
        lines.append("- Cloud vs On-Premise = Hybrid strategy or migration in progress")
        lines.append("")
        
        return "\n".join(lines)
    
    def _get_dashboard_path(self) -> Path:
        """Get path to dashboard markdown file"""
        target_dir = self.vault_dir / "Targets" / self.graph.target_sld
        dashboard_file = target_dir / f"Dashboard_{self.graph.target_sld}.md"
        return dashboard_file
    
    def _append_section(self, filepath: Path, content: str) -> None:
        """
        Append content section to markdown file
        Safe handling of existing content
        """
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        # Check if visualizations already exist
        if filepath.exists():
            with open(filepath, 'r', encoding='utf-8') as f:
                existing = f.read()
            
            # Skip if already has attack surface map
            if '🎯 Attack Surface Map' in existing:
                logger.info(f"Visualization sections already present in {filepath.name}")
                return
        
        # Append new content
        try:
            with open(filepath, 'a', encoding='utf-8') as f:
                f.write("\n")
                f.write("---\n")
                f.write(f"*Visualizations generated: {datetime.now().isoformat()}*\n")
                f.write(content)
            
            logger.info(f"✓ Injected visualization into {filepath.name}")
        
        except Exception as e:
            logger.error(f"Error appending to {filepath}: {e}")
            raise
