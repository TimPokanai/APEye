"""
Secret Detection Patterns Module
Contains regex patterns for detecting various types of sensitive information.
"""

import re
from dataclasses import dataclass
from typing import List, Tuple, Optional

@dataclass
class SecretMatch:
    """Represents a detected secret in code."""
    secret_type: str
    matched_value: str
    line_number: int
    file_path: str
    severity: str  # 'high', 'medium', 'low'

SECRET_PATTERNS = [

]

class SecretScanner:
    """Scans text content for potential secrets and sensitive information."""
    
    def __init__(self, custom_patterns: Optional[List[dict]] = None):
        """
        Initialize the scanner with default and optional custom patterns.
        
        Args:
            custom_patterns: Additional patterns to include in scanning
        """
        self.patterns = SECRET_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        
        # Compile patterns for efficiency
        self.compiled_patterns = [
            {
                "name": p["name"],
                "regex": re.compile(p["pattern"]),
                "severity": p["severity"]
            }
            for p in self.patterns
        ]
    
    def scan_text(self, text: str, file_path: str = "unknown") -> List[SecretMatch]:
        """
        Scan text content for secrets.
        
        Args:
            text: The text content to scan
            file_path: The file path for reporting purposes
            
        Returns:
            List of SecretMatch objects for detected secrets
        """
        matches = []
        lines = text.split('\n')

        for line_num, line in enumerate(lines, start=1):
            # Skip empty lines and comments
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue
            
            for pattern in self.compiled_patterns:
                found = pattern["regex"].search(line)
                if found:
                    # Get the matched value, using group 1 if available (for capture groups)
                    matched_value = found.group(1) if found.lastindex else found.group(0)
                    
                    # Mask the secret for safe display
                    masked_value = self._mask_secret(matched_value)
                    
                    matches.append(SecretMatch(
                        secret_type=pattern["name"],
                        matched_value=masked_value,
                        line_number=line_num,
                        file_path=file_path,
                        severity=pattern["severity"]
                    ))
        
        return matches
    
    def scan_diff(self, diff_content: str, file_path: str = "unknown") -> List[SecretMatch]:
        """
        Scan a Git diff for secrets (only in added lines).
        
        Args:
            diff_content: The diff content to scan
            file_path: The file path for reporting purposes
            
        Returns:
            List of SecretMatch objects for detected secrets
        """
        matches = []
        lines = diff_content.split('\n')
        current_line_num = 0
        
        for line in lines:
            # Track line numbers from diff headers
            if line.startswith('@@'):
                # Parse the line number from diff header: @@ -start,count +start,count @@
                match = re.search(r'\+(\d+)', line)
                if match:
                    current_line_num = int(match.group(1)) - 1
                continue
            
            # Only scan added lines (lines starting with +, but not +++)
            if line.startswith('+') and not line.startswith('+++'):
                current_line_num += 1
                content = line[1:]  # Remove the + prefix
                
                for pattern in self.compiled_patterns:
                    found = pattern["regex"].search(content)
                    if found:
                        matched_value = found.group(1) if found.lastindex else found.group(0)
                        masked_value = self._mask_secret(matched_value)
                        
                        matches.append(SecretMatch(
                            secret_type=pattern["name"],
                            matched_value=masked_value,
                            line_number=current_line_num,
                            file_path=file_path,
                            severity=pattern["severity"]
                        ))
            elif not line.startswith('-'):
                current_line_num += 1
        
        return matches
    
    def _mask_secret(self, secret: str) -> str:
        """
        Mask a secret for safe display, showing only first and last few characters.
        
        Args:
            secret: The secret string to mask
            
        Returns:
            Masked version of the secret
        """
        if len(secret) <= 8:
            return '*' * len(secret)
        return f"{secret[:4]}...{secret[-4:]}"
    
    def get_severity_icon(self, severity: str) -> str:
        """Get an icon for the severity level."""
        return {
            "high": "🔴",
            "medium": "🟠",
            "low": "🟡"
        }.get(severity, "⚪")

def format_findings_report(matches: List[SecretMatch]) -> str:
    """
    Format detected secrets into a readable report.
    
    Args:
        matches: List of SecretMatch objects
        
    Returns:
        Formatted report string
    """
    if not matches:
        return "No secrets detected."
    
    scanner = SecretScanner()
    
    # Group by severity
    high = [m for m in matches if m.severity == "high"]
    medium = [m for m in matches if m.severity == "medium"]
    low = [m for m in matches if m.severity == "low"]
    
    report_lines = [
        "## 🔐 Secret Scanner Report",
        "",
        f"**Total findings: {len(matches)}** (🔴 High: {len(high)}, 🟠 Medium: {len(medium)}, 🟡 Low: {len(low)})",
        "",
        "---",
        ""
    ]
    
    for severity_name, severity_matches in [("High", high), ("Medium", medium), ("Low", low)]:
        if severity_matches:
            severity_icon = scanner.get_severity_icon(severity_name.lower())
            report_lines.append(f"### {severity_icon} {severity_name} Severity")
            report_lines.append("")
            
            for match in severity_matches:
                report_lines.append(f"- **{match.secret_type}**")
                report_lines.append(f"  - File: `{match.file_path}`")
                report_lines.append(f"  - Line: {match.line_number}")
                report_lines.append(f"  - Value: `{match.matched_value}`")
                report_lines.append("")
    
    report_lines.extend([
        "---",
        "",
        "⚠️ **Action Required**: Please remove or rotate the detected secrets immediately.",
        "",
        "**Recommended steps:**",
        "1. Remove the sensitive data from your code",
        "2. Use environment variables or a secrets manager",
        "3. Rotate any exposed credentials",
        "4. Check your git history and consider rewriting it if needed",
        "",
        "*This scan was performed automatically by the APEye Bot.*"
    ])
    
    return '\n'.join(report_lines)
