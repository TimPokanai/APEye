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

from secret_patterns import SecretScanner, SecretMatch, format_findings_report
from metrics import get_metrics, MetricsStorage

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
        self.github = Github(access_token, per_page=100)
        self.scanner = SecretScanner()
        self.metrics = get_metrics(metrics_path)
        self._processed_prs: Set[str] = set()  # Track processed PRs to avoid duplicates
        self._processed_repos: Set[str] = set()  # Track repos checked in current session

        # Verify authentication of access token
        try:
            user = self.github.get_user()
            logger.info(f"Authenticated as: {user.login}")
        except GithubException as e:
            logger.error(f"Authentication failed: {e}")
            raise

    def get_repositories(self, org_name: Optional[str] = None, 
                         repo_names: Optional[List[str]] = None) -> Generator[Repository, None, None]:
        """
        Get repositories to monitor.
        
        Args:
            org_name: Organization name to get all repos from (optional)
            repo_names: List of specific repo names in 'owner/repo' format (optional)
            
        Yields:
            Repository objects
        """
        if repo_names:
            for repo_name in repo_names:
                try:
                    yield self.github.get_repo(repo_name)
                except GithubException as e:
                    logger.error(f"Failed to get repo {repo_name}: {e}")
                    
        elif org_name:
            try:
                org = self.github.get_organization(org_name)
                for repo in org.get_repos():
                    yield repo
            except GithubException as e:
                logger.error(f"Failed to get org repos for {org_name}: {e}")
        else:
            # Get authenticated user's repos
            user = self.github.get_user()
            for repo in user.get_repos():
                yield repo
    
    
