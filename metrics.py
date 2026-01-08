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

@dataclass 
class GlobalMetrics:
    """Global metrics across all repositories."""
    total_repositories_scanned: int = 0
    total_prs_scanned: int = 0
    total_secrets_found: int = 0
    total_comments_posted: int = 0
    total_high_severity: int = 0
    total_medium_severity: int = 0
    total_low_severity: int = 0
    started_at: str = ""
    last_updated: str = ""
    secret_types_breakdown: Dict[str, int] = field(default_factory=dict)
    top_vulnerable_repos: List[Dict[str, Any]] = field(default_factory=list)

class MetricsStorage:
    """
    Persistent storage for scanner metrics.
    Thread-safe implementation for concurrent access.
    """
    
    def __init__(self, storage_path: str = "scanner_metrics.json"):
        """
        Initialize the metrics storage.
        
        Args:
            storage_path: Path to the JSON file for persistent storage
        """
        self.storage_path = Path(storage_path)
        self._lock = threading.RLock()
        self._data: Dict[str, Any] = {
            "global_metrics": {},
            "repository_stats": {},
            "scan_history": []
        }
        self._load()
    
    def _load(self):
        """Load metrics from persistent storage."""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r') as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load metrics file: {e}")
                self._initialize_empty()
        else:
            self._initialize_empty()
    
    def _initialize_empty(self):
        """Initialize empty metrics structure."""
        self._data = {
            "global_metrics": asdict(GlobalMetrics(
                started_at=datetime.now().isoformat()
            )),
            "repository_stats": {},
            "scan_history": []
        }
        self._save()

    def _save(self):
        """Save metrics to persistent storage."""
        try:
            with open(self.storage_path, 'w') as f:
                json.dump(self._data, f, indent=2, default=str)
        except IOError as e:
            print(f"Warning: Could not save metrics file: {e}")
    