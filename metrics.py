"""
Metrics Storage Module
Tracks statistics for the secret scanner bot across all scanned repositories.
"""

import json
import os
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path

@dataclass
class ScanResult:
    """Individual scan result record."""
    timestamp: str
    full_repo_name: str
    pr_number: int
    pr_title: str
    author: str
    secrets_found: int
    secret_types: List[str]
    comment_posted: bool
    severity_breakdown: Dict[str, int]

@dataclass
class RepositoryStats:
    """Statistics for a single repository."""
    full_repo_name: str
    total_scans: int = 0
    total_secrets_found: int = 0
    total_comments_posted: int = 0
    first_scanned: str = ""
    last_scanned: str = ""
    prs_scanned: List[int] = field(default_factory=list)
    secret_types_found: Dict[str, int] = field(default_factory=dict)
