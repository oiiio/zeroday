"""
Git Operations - Utilities for repository cloning and management
"""

import os
import shutil
from typing import Optional, Dict, Any
import git
from git import Repo


class GitOperations:
    """Utility class for Git operations"""
    
    @staticmethod
    def clone_repository(
        repo_url: str, 
        local_path: str, 
        depth: int = 1,
        branch: Optional[str] = None
    ) -> Repo:
        """
        Clone a Git repository
        
        Args:
            repo_url: URL of the repository to clone
            local_path: Local path where to clone the repository
            depth: Clone depth (1 for shallow clone)
            branch: Specific branch to clone
            
        Returns:
            Git Repo object
        """
        # Remove existing directory if it exists
        if os.path.exists(local_path):
            shutil.rmtree(local_path)
        
        # Clone repository
        clone_kwargs = {
            'depth': depth if depth > 0 else None
        }
        
        if branch:
            clone_kwargs['branch'] = branch
            
        repo = Repo.clone_from(repo_url, local_path, **clone_kwargs)
        return repo
    
    @staticmethod
    def get_repository_info(repo: Repo) -> Dict[str, Any]:
        """
        Get information about a Git repository
        
        Args:
            repo: Git Repo object
            
        Returns:
            Dict containing repository information
        """
        try:
            # Get basic repository info
            info = {
                'url': next(repo.remotes.origin.urls),
                'branch': repo.active_branch.name,
                'commit_hash': repo.head.commit.hexsha,
                'commit_message': repo.head.commit.message.strip(),
                'author': str(repo.head.commit.author),
                'commit_date': repo.head.commit.committed_datetime.isoformat(),
                'is_dirty': repo.is_dirty(),
                'untracked_files': repo.untracked_files
            }
            
            # Get commit count
            try:
                info['commit_count'] = len(list(repo.iter_commits()))
            except:
                info['commit_count'] = 0
            
            # Get contributors
            try:
                contributors = set()
                for commit in repo.iter_commits(max_count=100):  # Last 100 commits
                    contributors.add(str(commit.author))
                info['recent_contributors'] = list(contributors)
            except:
                info['recent_contributors'] = []
            
            return info
            
        except Exception as e:
            return {
                'error': f"Failed to get repository info: {str(e)}",
                'url': 'unknown',
                'branch': 'unknown',
                'commit_hash': 'unknown'
            }
    
    @staticmethod
    def get_file_history(repo: Repo, file_path: str, max_commits: int = 10) -> list:
        """
        Get commit history for a specific file
        
        Args:
            repo: Git Repo object
            file_path: Path to the file relative to repo root
            max_commits: Maximum number of commits to retrieve
            
        Returns:
            List of commit information for the file
        """
        try:
            commits = []
            for commit in repo.iter_commits(paths=file_path, max_count=max_commits):
                commits.append({
                    'hash': commit.hexsha,
                    'message': commit.message.strip(),
                    'author': str(commit.author),
                    'date': commit.committed_datetime.isoformat(),
                    'files_changed': len(commit.stats.files)
                })
            return commits
        except Exception as e:
            return [{'error': f"Failed to get file history: {str(e)}"}]
    
    @staticmethod
    def calculate_directory_size(directory: str) -> float:
        """
        Calculate directory size in MB
        
        Args:
            directory: Path to directory
            
        Returns:
            Size in MB
        """
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(directory):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(filepath)
                except (OSError, IOError):
                    pass
        return total_size / (1024 * 1024)  # Convert to MB
    
    @staticmethod
    def cleanup_repository(local_path: str) -> bool:
        """
        Clean up a cloned repository
        
        Args:
            local_path: Path to the repository to clean up
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if os.path.exists(local_path):
                shutil.rmtree(local_path)
                return True
            return True
        except Exception:
            return False
