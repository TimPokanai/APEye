"""
GitHub API Client Module
Handles all interactions with GitHub's API for PR monitoring and commenting.
"""

import os
import logging
import time
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Generator, Set
from dataclasses import dataclass

from github import Github, GithubException, RateLimitExceededException
from github.PullRequest import PullRequest
from github.Repository import Repository

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class PRInfo:
    """Information about a Pull Request."""
    full_repo_name: str
    pr_number: int
    pr_title: str
    pr_url: str
    author: str
    created_at: datetime
    files_changed: int

class GitHubClient:
    """Client for interacting with GitHub API."""

    def __init__(self, access_token: str, metrics_path: str = "APEye_metrics.json"):
        """
        Initialize the GitHub client.
        
        Args:
            access_token: GitHub Personal Access Token with repo permissions
            metrics_path: Path to metrics storage file
        """
        self.github = GitHub(access_token, per_page=100)
