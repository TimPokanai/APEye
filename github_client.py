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
    
    def search_public_repos_with_recent_activity(self, 
                                                  since_minutes: int = 30,
                                                  language: Optional[str] = None,
                                                  min_stars: int = 0,
                                                  max_results: int = 100) -> Generator[Repository, None, None]:
        """
        Search for public repositories with recent push activity.
        
        Args:
            since_minutes: Look for repos pushed within this many minutes
            language: Optional programming language filter
            min_stars: Minimum number of stars
            max_results: Maximum number of repositories to return
            
        Yields:
            Repository objects with recent activity
        """
        since_date = datetime.now() - timedelta(minutes=since_minutes)
        date_str = since_date.strftime('%Y-%m-%dT%H:%M:%S')
        
        # Build search query
        query_parts = [f"pushed:>={date_str}"]
        
        if language:
            query_parts.append(f"language:{language}")
        
        if min_stars > 0:
            query_parts.append(f"stars:>={min_stars}")
        
        query = " ".join(query_parts)
        
        logger.info(f"Searching public repos with query: {query}")
        
        try:
            repos = self.github.search_repositories(
                query=query,
                sort="updated",
                order="desc"
            )
            
            count = 0
            for repo in repos:
                if count >= max_results:
                    break
                    
                # Skip repos we've already processed this session
                if repo.full_name in self._processed_repos:
                    continue
                
                self._processed_repos.add(repo.full_name)
                yield repo
                count += 1
                
                # Complying to Github API rate limits
                if count % 10 == 0:
                    self._check_rate_limit()
                    
        except RateLimitExceededException:
            logger.warning("Rate limit exceeded during repo search")
            self._wait_for_rate_limit()
        except GithubException as e:
            logger.error(f"Failed to search repositories: {e}")
    
