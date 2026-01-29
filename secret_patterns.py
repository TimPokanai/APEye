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

# Secret patterns with their descriptions and severity levels
SECRET_PATTERNS = [
    # AWS
    {
        "name": "AWS Access Key ID",
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "severity": "high"
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "high"
    },
    
    # GitHub
    {
        "name": "GitHub Personal Access Token",
        "pattern": r"ghp_[A-Za-z0-9]{36}",
        "severity": "high"
    },
    {
        "name": "GitHub OAuth Access Token",
        "pattern": r"gho_[A-Za-z0-9]{36}",
        "severity": "high"
    },
    {
        "name": "GitHub App Token",
        "pattern": r"(?:ghu|ghs)_[A-Za-z0-9]{36}",
        "severity": "high"
    },
    {
        "name": "GitHub Refresh Token",
        "pattern": r"ghr_[A-Za-z0-9]{36}",
        "severity": "high"
    },
    
    # Google
    {
        "name": "Google API Key",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "high"
    },
    {
        "name": "Google OAuth Client Secret",
        "pattern": r"(?i)client[_\-]?secret[\s]*[=:]\s*['\"]?([A-Za-z0-9_\-]{24})['\"]?",
        "severity": "medium"
    },
    
    # Stripe
    {
        "name": "Stripe Live Secret Key",
        "pattern": r"sk_live_[A-Za-z0-9]{24,}",
        "severity": "high"
    },
    {
        "name": "Stripe Test Secret Key",
        "pattern": r"sk_test_[A-Za-z0-9]{24,}",
        "severity": "medium"
    },
    {
        "name": "Stripe Restricted Key",
        "pattern": r"rk_live_[A-Za-z0-9]{24,}",
        "severity": "high"
    },
    
    # Slack
    {
        "name": "Slack Bot Token",
        "pattern": r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}",
        "severity": "high"
    },
    {
        "name": "Slack User Token",
        "pattern": r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}",
        "severity": "high"
    },
    {
        "name": "Slack Webhook URL",
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}",
        "severity": "high"
    },
    
    # Discord
    {
        "name": "Discord Bot Token",
        "pattern": r"(?:N|M|O)[A-Za-z0-9]{23,}\.[\w-]{6}\.[\w-]{27}",
        "severity": "high"
    },
    {
        "name": "Discord Webhook URL",
        "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
        "severity": "medium"
    },
    
    # Twilio
    {
        "name": "Twilio Account SID",
        "pattern": r"AC[a-f0-9]{32}",
        "severity": "medium"
    },
    {
        "name": "Twilio Auth Token",
        "pattern": r"(?i)twilio[_\-\.]?auth[_\-\.]?token[\s]*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",
        "severity": "high"
    },
    
    # SendGrid
    {
        "name": "SendGrid API Key",
        "pattern": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
        "severity": "high"
    },
    
    # Mailchimp
    {
        "name": "Mailchimp API Key",
        "pattern": r"[a-f0-9]{32}-us[0-9]{1,2}",
        "severity": "high"
    },
    
    # Heroku
    {
        "name": "Heroku API Key",
        "pattern": r"(?i)heroku[_\-\.]?api[_\-\.]?key[\s]*[=:]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?",
        "severity": "high"
    },
    
    # NPM
    {
        "name": "NPM Access Token",
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "severity": "high"
    },
    
    # PyPI
    {
        "name": "PyPI API Token",
        "pattern": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}",
        "severity": "high"
    },
    
    # Database Connection Strings
    {
        "name": "PostgreSQL Connection String",
        "pattern": r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/[^\s]+",
        "severity": "high"
    },
    {
        "name": "MongoDB Connection String",
        "pattern": r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s]+",
        "severity": "high"
    },
    {
        "name": "MySQL Connection String",
        "pattern": r"mysql://[^:]+:[^@]+@[^/]+/[^\s]+",
        "severity": "high"
    },
    {
        "name": "Redis Connection String",
        "pattern": r"redis://[^:]+:[^@]+@[^\s]+",
        "severity": "high"
    },
    
    # Generic Patterns
    {
        "name": "Private Key",
        "pattern": r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?:\sBLOCK)?-----",
        "severity": "high"
    },
    {
        "name": "Generic API Key Assignment",
        "pattern": r"(?i)(?:api[_\-\.]?key|apikey|secret[_\-\.]?key|auth[_\-\.]?token|access[_\-\.]?token)[\s]*[=:]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]",
        "severity": "medium"
    },
    {
        "name": "Generic Password Assignment",
        "pattern": r"(?i)(?:password|passwd|pwd)[\s]*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "severity": "medium"
    },
    {
        "name": "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
        "severity": "medium"
    },
    
    # Azure
    {
        "name": "Azure Storage Account Key",
        "pattern": r"(?i)(?:account[_\-\.]?key|storage[_\-\.]?key)[\s]*[=:]\s*['\"]?([A-Za-z0-9+/]{86}==)['\"]?",
        "severity": "high"
    },
    {
        "name": "Azure Connection String",
        "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]+=*;",
        "severity": "high"
    },
    
    # Firebase
    {
        "name": "Firebase Database URL",
        "pattern": r"https://[a-z0-9-]+\.firebaseio\.com",
        "severity": "medium"
    },
    
    # OpenAI
    {
        "name": "OpenAI API Key",
        "pattern": r"sk-[A-Za-z0-9]{48}",
        "severity": "high"
    },
    
    # Anthropic
    {
        "name": "Anthropic API Key",
        "pattern": r"sk-ant-[A-Za-z0-9_\-]{93}",
        "severity": "high"
    },
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
