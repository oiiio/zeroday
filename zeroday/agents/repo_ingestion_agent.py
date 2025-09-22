"""
Repository Ingestion Agent - Handles cloning and preprocessing of Python repositories
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import git
from pydantic import BaseModel, Field

from .base_agent import BaseAgent, AgentConfig
from nat.profiler.decorators.function_tracking import track_function


class RepoIngestionConfig(AgentConfig):
    """Configuration for Repository Ingestion Agent"""
    max_repo_size_mb: int = Field(default=500, description="Maximum repository size in MB")
    temp_dir: str = Field(default="./data/repositories", description="Temporary directory for cloned repos")
    allowed_extensions: List[str] = Field(
        default=[".py", ".pyx", ".pyi", ".txt", ".md", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini"],
        description="Allowed file extensions for analysis"
    )
    excluded_dirs: List[str] = Field(
        default=[".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv", "env"],
        description="Directories to exclude from analysis"
    )
    clone_depth: int = Field(default=1, description="Git clone depth (1 for shallow clone)")


class RepositoryInfo(BaseModel):
    """Information about a cloned repository"""
    url: str
    local_path: str
    name: str
    size_mb: float
    python_files: List[str]
    total_files: int
    dependencies: List[str]
    readme_content: Optional[str] = None
    license_info: Optional[str] = None


class RepoIngestionAgent(BaseAgent):
    """
    Agent responsible for cloning and preprocessing Python repositories
    
    Capabilities:
    - Clone repositories from GitHub URLs
    - Filter and validate Python files
    - Extract repository metadata
    - Identify dependencies
    - Prepare files for security analysis
    """
    
    def __init__(self, config: RepoIngestionConfig):
        super().__init__(config)
        self.repo_config = config
        self._ensure_temp_dir()
    
    def _ensure_temp_dir(self) -> None:
        """Ensure temporary directory exists"""
        os.makedirs(self.repo_config.temp_dir, exist_ok=True)
    
    async def _initialize_agent_specific(self) -> None:
        """Initialize repository ingestion specific components"""
        self.logger.info("Repository Ingestion Agent initialized")
    
    @track_function(metadata={"agent_type": "ingestion", "operation": "execute_core"})
    async def _execute_core(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Core execution logic for repository ingestion
        
        Args:
            input_data: Must contain 'repo_url' key
            
        Returns:
            Dict containing repository information and file paths
        """
        if not self.validate_input(input_data):
            raise ValueError("Invalid input data")
            
        repo_url = input_data["repo_url"]
        self.logger.info(f"Starting ingestion of repository: {repo_url}")
        
        # Clone repository
        repo_info = await self._clone_repository(repo_url)
        
        # Analyze repository structure
        await self._analyze_repository_structure(repo_info)
        
        # Extract dependencies
        await self._extract_dependencies(repo_info)
        
        # Extract metadata
        await self._extract_metadata(repo_info)
        
        return {
            "status": "success",
            "repository_info": repo_info.dict(),
            "python_files": repo_info.python_files,
            "total_files": repo_info.total_files,
            "size_mb": repo_info.size_mb
        }
    
    def validate_input(self, input_data: Dict[str, Any]) -> bool:
        """Validate input contains required repository URL"""
        if not isinstance(input_data, dict):
            return False
        
        repo_url = input_data.get("repo_url")
        if not repo_url or not isinstance(repo_url, str):
            return False
            
        # Basic URL validation
        try:
            parsed = urlparse(repo_url)
            return parsed.scheme in ["http", "https"] and parsed.netloc
        except Exception:
            return False
    
    @track_function(metadata={"agent_type": "ingestion", "operation": "clone_repository"})
    async def _clone_repository(self, repo_url: str) -> RepositoryInfo:
        """Clone repository to temporary directory"""
        # Extract repository name from URL
        repo_name = self._extract_repo_name(repo_url)
        local_path = os.path.join(self.repo_config.temp_dir, repo_name)
        
        # Remove existing directory if it exists
        if os.path.exists(local_path):
            shutil.rmtree(local_path)
        
        try:
            self.logger.info(f"Cloning repository to: {local_path}")
            
            # Clone with specified depth
            repo = git.Repo.clone_from(
                repo_url, 
                local_path,
                depth=self.repo_config.clone_depth
            )
            
            # Calculate repository size
            size_mb = self._calculate_directory_size(local_path)
            
            # Check size limit
            if size_mb > self.repo_config.max_repo_size_mb:
                shutil.rmtree(local_path)
                raise ValueError(f"Repository size ({size_mb:.1f}MB) exceeds limit ({self.repo_config.max_repo_size_mb}MB)")
            
            self.logger.info(f"Successfully cloned repository ({size_mb:.1f}MB)")
            
            return RepositoryInfo(
                url=repo_url,
                local_path=local_path,
                name=repo_name,
                size_mb=size_mb,
                python_files=[],
                total_files=0,
                dependencies=[]
            )
            
        except Exception as e:
            self.logger.error(f"Failed to clone repository: {str(e)}")
            if os.path.exists(local_path):
                shutil.rmtree(local_path)
            raise
    
    def _extract_repo_name(self, repo_url: str) -> str:
        """Extract repository name from URL"""
        parsed = urlparse(repo_url)
        path_parts = parsed.path.strip('/').split('/')
        
        if len(path_parts) >= 2:
            # Format: owner/repo or owner/repo.git
            repo_name = path_parts[-1]
            if repo_name.endswith('.git'):
                repo_name = repo_name[:-4]
            return f"{path_parts[-2]}_{repo_name}"
        
        return "unknown_repo"
    
    def _calculate_directory_size(self, directory: str) -> float:
        """Calculate directory size in MB"""
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(directory):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(filepath)
                except (OSError, IOError):
                    pass
        return total_size / (1024 * 1024)  # Convert to MB
    
    @track_function(metadata={"agent_type": "ingestion", "operation": "analyze_structure"})
    async def _analyze_repository_structure(self, repo_info: RepositoryInfo) -> None:
        """Analyze repository structure and identify Python files"""
        python_files = []
        total_files = 0
        
        for root, dirs, files in os.walk(repo_info.local_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.repo_config.excluded_dirs]
            
            for file in files:
                total_files += 1
                file_path = os.path.join(root, file)
                
                # Check if file has allowed extension
                if any(file.endswith(ext) for ext in self.repo_config.allowed_extensions):
                    if file.endswith('.py'):
                        python_files.append(file_path)
        
        repo_info.python_files = python_files
        repo_info.total_files = total_files
        
        self.logger.info(f"Found {len(python_files)} Python files out of {total_files} total files")
    
    @track_function(metadata={"agent_type": "ingestion", "operation": "extract_dependencies"})
    async def _extract_dependencies(self, repo_info: RepositoryInfo) -> None:
        """Extract Python dependencies from requirements files"""
        dependencies = []
        
        # Common dependency files
        dependency_files = [
            "requirements.txt",
            "requirements-dev.txt", 
            "requirements-test.txt",
            "pyproject.toml",
            "setup.py",
            "Pipfile"
        ]
        
        for dep_file in dependency_files:
            file_path = os.path.join(repo_info.local_path, dep_file)
            if os.path.exists(file_path):
                try:
                    deps = await self._parse_dependency_file(file_path, dep_file)
                    dependencies.extend(deps)
                except Exception as e:
                    self.logger.warning(f"Failed to parse {dep_file}: {str(e)}")
        
        # Remove duplicates and sort
        repo_info.dependencies = sorted(list(set(dependencies)))
        self.logger.info(f"Found {len(repo_info.dependencies)} dependencies")
    
    async def _parse_dependency_file(self, file_path: str, filename: str) -> List[str]:
        """Parse dependency file and extract package names"""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if filename == "requirements.txt" or filename.startswith("requirements"):
                # Parse requirements.txt format
                for line in content.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#') and not line.startswith('-'):
                        # Extract package name (before version specifiers)
                        pkg_name = line.split('==')[0].split('>=')[0].split('<=')[0].split('>')[0].split('<')[0].split('~=')[0].strip()
                        if pkg_name:
                            dependencies.append(pkg_name)
            
            elif filename == "pyproject.toml":
                # Basic parsing for pyproject.toml dependencies
                import re
                deps_match = re.findall(r'"([^"]+)"', content)
                for dep in deps_match:
                    if '==' in dep or '>=' in dep or '<=' in dep:
                        pkg_name = dep.split('==')[0].split('>=')[0].split('<=')[0].strip()
                        if pkg_name and not pkg_name.startswith('-'):
                            dependencies.append(pkg_name)
            
            elif filename == "setup.py":
                # Basic parsing for setup.py
                import re
                install_requires_match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
                if install_requires_match:
                    deps_str = install_requires_match.group(1)
                    deps = re.findall(r'"([^"]+)"', deps_str)
                    for dep in deps:
                        pkg_name = dep.split('==')[0].split('>=')[0].split('<=')[0].strip()
                        if pkg_name:
                            dependencies.append(pkg_name)
                            
        except Exception as e:
            self.logger.warning(f"Error parsing {filename}: {str(e)}")
        
        return dependencies
    
    @track_function(metadata={"agent_type": "ingestion", "operation": "extract_metadata"})
    async def _extract_metadata(self, repo_info: RepositoryInfo) -> None:
        """Extract repository metadata (README, LICENSE, etc.)"""
        # Extract README content
        readme_files = ["README.md", "README.txt", "README.rst", "README"]
        for readme_file in readme_files:
            readme_path = os.path.join(repo_info.local_path, readme_file)
            if os.path.exists(readme_path):
                try:
                    with open(readme_path, 'r', encoding='utf-8') as f:
                        repo_info.readme_content = f.read()[:5000]  # Limit to first 5000 chars
                    break
                except Exception as e:
                    self.logger.warning(f"Failed to read {readme_file}: {str(e)}")
        
        # Extract LICENSE information
        license_files = ["LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING"]
        for license_file in license_files:
            license_path = os.path.join(repo_info.local_path, license_file)
            if os.path.exists(license_path):
                try:
                    with open(license_path, 'r', encoding='utf-8') as f:
                        repo_info.license_info = f.read()[:1000]  # Limit to first 1000 chars
                    break
                except Exception as e:
                    self.logger.warning(f"Failed to read {license_file}: {str(e)}")
    
    @track_function(metadata={"agent_type": "ingestion", "operation": "cleanup"})
    async def cleanup(self) -> None:
        """Cleanup cloned repositories"""
        await super().cleanup()
        
        # Optionally clean up temporary directories
        # This could be configurable based on user preference
        if os.path.exists(self.repo_config.temp_dir):
            self.logger.info(f"Temporary repositories remain in: {self.repo_config.temp_dir}")
            # Uncomment to auto-cleanup:
            # shutil.rmtree(self.repo_config.temp_dir)
