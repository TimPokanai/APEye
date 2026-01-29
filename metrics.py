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
    
    def record_scan(self, 
                    repo_full_name: str,
                    pr_number: int,
                    pr_title: str,
                    author: str,
                    secrets_found: int,
                    secret_types: List[str],
                    comment_posted: bool,
                    severity_breakdown: Dict[str, int]):
        """
        Record a scan result.
        
        Args:
            repo_full_name: Full name of the repository (owner/repo)
            pr_number: Pull request number
            pr_title: Title of the pull request
            author: PR author username
            secrets_found: Number of secrets found
            secret_types: List of secret type names found
            comment_posted: Whether a comment was posted
            severity_breakdown: Dict with 'high', 'medium', 'low' counts
        """
        with self._lock:
            timestamp = datetime.now().isoformat()
            
            # Create scan result record
            scan_result = ScanResult(
                timestamp=timestamp,
                repo_full_name=repo_full_name,
                pr_number=pr_number,
                pr_title=pr_title,
                author=author,
                secrets_found=secrets_found,
                secret_types=secret_types,
                comment_posted=comment_posted,
                severity_breakdown=severity_breakdown
            )
            
            # Add to scan history (keep last 10000 entries)
            self._data["scan_history"].append(asdict(scan_result))
            if len(self._data["scan_history"]) > 10000:
                self._data["scan_history"] = self._data["scan_history"][-10000:]
            
            # Update repository stats
            self._update_repo_stats(repo_full_name, pr_number, secrets_found, 
                                   secret_types, comment_posted, timestamp)
            
            # Update global metrics
            self._update_global_metrics(repo_full_name, secrets_found, secret_types,
                                       comment_posted, severity_breakdown)
            
            self._save()
    
    def _update_repo_stats(self, repo_full_name: str, pr_number: int,
                           secrets_found: int, secret_types: List[str],
                           comment_posted: bool, timestamp: str):
        """Update statistics for a specific repository."""
        if repo_full_name not in self._data["repository_stats"]:
            self._data["repository_stats"][repo_full_name] = asdict(RepositoryStats(
                repo_full_name=repo_full_name,
                first_scanned=timestamp
            ))
        
        stats = self._data["repository_stats"][repo_full_name]
        stats["total_scans"] += 1
        stats["total_secrets_found"] += secrets_found
        stats["last_scanned"] = timestamp
        
        if comment_posted:
            stats["total_comments_posted"] += 1
        
        if pr_number not in stats["prs_scanned"]:
            stats["prs_scanned"].append(pr_number)
            # Keep only last 1000 PR numbers per repo
            if len(stats["prs_scanned"]) > 1000:
                stats["prs_scanned"] = stats["prs_scanned"][-1000:]
        
        # Track secret types for this repo
        for secret_type in secret_types:
            if secret_type not in stats["secret_types_found"]:
                stats["secret_types_found"][secret_type] = 0
            stats["secret_types_found"][secret_type] += 1
    
    def _update_global_metrics(self, repo_full_name: str, secrets_found: int,
                               secret_types: List[str], comment_posted: bool,
                               severity_breakdown: Dict[str, int]):
        """Update global metrics."""
        metrics = self._data["global_metrics"]
        
        # Count unique repositories
        metrics["total_repositories_scanned"] = len(self._data["repository_stats"])
        
        metrics["total_prs_scanned"] += 1
        metrics["total_secrets_found"] += secrets_found
        
        if comment_posted:
            metrics["total_comments_posted"] += 1
        
        # Update severity counts
        metrics["total_high_severity"] += severity_breakdown.get("high", 0)
        metrics["total_medium_severity"] += severity_breakdown.get("medium", 0)
        metrics["total_low_severity"] += severity_breakdown.get("low", 0)
        
        metrics["last_updated"] = datetime.now().isoformat()
        
        # Track secret types globally
        for secret_type in secret_types:
            if secret_type not in metrics["secret_types_breakdown"]:
                metrics["secret_types_breakdown"][secret_type] = 0
            metrics["secret_types_breakdown"][secret_type] += 1
        
        # Update top vulnerable repos
        self._update_top_vulnerable_repos()
    
    def _update_top_vulnerable_repos(self, limit: int = 20):
        """Update the list of most vulnerable repositories."""
        repo_stats = self._data["repository_stats"]
        
        # Sort by total secrets found
        sorted_repos = sorted(
            repo_stats.items(),
            key=lambda x: x[1]["total_secrets_found"],
            reverse=True
        )[:limit]
        
        self._data["global_metrics"]["top_vulnerable_repos"] = [
            {
                "repo": name,
                "secrets_found": stats["total_secrets_found"],
                "comments_posted": stats["total_comments_posted"],
                "last_scanned": stats["last_scanned"]
            }
            for name, stats in sorted_repos if stats["total_secrets_found"] > 0
        ]
