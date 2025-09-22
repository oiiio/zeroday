"""
Base Agent class for ZeroDay Pipeline with NeMo Agent Toolkit integration
"""

import os
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

from nat.core import register_function, Builder
from nat.core.types import LLMFrameworkEnum
from nat.profiler.decorators.function_tracking import track_function


class AgentConfig(BaseModel):
    """Base configuration for all agents"""
    name: str = Field(..., description="Agent name")
    description: str = Field(..., description="Agent description")
    llm_name: str = Field(default="deephat_llm", description="LLM model name to use")
    max_retries: int = Field(default=3, description="Maximum number of retries for failed operations")
    timeout_seconds: int = Field(default=300, description="Timeout for agent operations")
    enable_profiling: bool = Field(default=True, description="Enable NeMo profiling")
    log_level: str = Field(default="INFO", description="Logging level")


class BaseAgent(ABC):
    """
    Base agent class with NeMo Agent Toolkit integration
    
    Provides common functionality for all agents including:
    - NeMo profiling and observability
    - Error handling and retries
    - Logging
    - Configuration management
    """
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.logger = self._setup_logging()
        self.builder: Optional[Builder] = None
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for the agent"""
        logger = logging.getLogger(f"zeroday.agents.{self.config.name}")
        logger.setLevel(getattr(logging, self.config.log_level.upper()))
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    @track_function(metadata={"agent_type": "base", "operation": "initialize"})
    async def initialize(self, builder: Builder) -> None:
        """Initialize the agent with NeMo Builder"""
        self.builder = builder
        self.logger.info(f"Initializing agent: {self.config.name}")
        await self._initialize_agent_specific()
        
    @abstractmethod
    async def _initialize_agent_specific(self) -> None:
        """Agent-specific initialization logic"""
        pass
    
    @track_function(metadata={"agent_type": "base", "operation": "execute"})
    async def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the agent's main functionality with error handling and retries
        
        Args:
            input_data: Input data for the agent
            
        Returns:
            Dict containing the agent's output
        """
        for attempt in range(self.config.max_retries):
            try:
                self.logger.info(f"Executing agent {self.config.name}, attempt {attempt + 1}")
                result = await self._execute_core(input_data)
                self.logger.info(f"Agent {self.config.name} completed successfully")
                return result
                
            except Exception as e:
                self.logger.error(f"Agent {self.config.name} failed on attempt {attempt + 1}: {str(e)}")
                if attempt == self.config.max_retries - 1:
                    raise
                await self._handle_retry(attempt, e)
                
        raise RuntimeError(f"Agent {self.config.name} failed after {self.config.max_retries} attempts")
    
    @abstractmethod
    async def _execute_core(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Core execution logic - to be implemented by subclasses"""
        pass
    
    async def _handle_retry(self, attempt: int, error: Exception) -> None:
        """Handle retry logic - can be overridden by subclasses"""
        import asyncio
        wait_time = 2 ** attempt  # Exponential backoff
        self.logger.info(f"Retrying in {wait_time} seconds...")
        await asyncio.sleep(wait_time)
    
    @track_function(metadata={"agent_type": "base", "operation": "validate_input"})
    def validate_input(self, input_data: Dict[str, Any]) -> bool:
        """Validate input data - can be overridden by subclasses"""
        return isinstance(input_data, dict)
    
    @track_function(metadata={"agent_type": "base", "operation": "cleanup"})
    async def cleanup(self) -> None:
        """Cleanup resources - can be overridden by subclasses"""
        self.logger.info(f"Cleaning up agent: {self.config.name}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status information"""
        return {
            "name": self.config.name,
            "description": self.config.description,
            "initialized": self.builder is not None,
            "config": self.config.dict()
        }


class SecurityAgentConfig(AgentConfig):
    """Extended configuration for security-focused agents"""
    vulnerability_confidence_threshold: float = Field(
        default=0.7, 
        description="Minimum confidence threshold for vulnerability detection"
    )
    max_file_size_kb: int = Field(
        default=100, 
        description="Maximum file size to analyze in KB"
    )
    enable_zero_day_detection: bool = Field(
        default=True, 
        description="Enable advanced zero-day vulnerability detection"
    )
    analysis_depth: str = Field(
        default="deep", 
        choices=["shallow", "medium", "deep"],
        description="Analysis depth level"
    )


class SecurityBaseAgent(BaseAgent):
    """Base class for security-focused agents"""
    
    def __init__(self, config: SecurityAgentConfig):
        super().__init__(config)
        self.security_config = config
    
    @track_function(metadata={"agent_type": "security", "operation": "filter_files"})
    def filter_analyzable_files(self, files: List[str]) -> List[str]:
        """Filter files that can be analyzed based on size and type"""
        analyzable_files = []
        
        for file_path in files:
            try:
                if os.path.exists(file_path):
                    file_size_kb = os.path.getsize(file_path) / 1024
                    if file_size_kb <= self.security_config.max_file_size_kb:
                        analyzable_files.append(file_path)
                    else:
                        self.logger.warning(f"Skipping large file: {file_path} ({file_size_kb:.1f}KB)")
                        
            except Exception as e:
                self.logger.error(f"Error checking file {file_path}: {str(e)}")
                
        return analyzable_files
    
    @track_function(metadata={"agent_type": "security", "operation": "assess_confidence"})
    def assess_vulnerability_confidence(self, vulnerability_data: Dict[str, Any]) -> float:
        """Assess confidence level of a detected vulnerability"""
        # Base implementation - can be overridden by specific agents
        confidence_factors = []
        
        # Factor in detection method
        if vulnerability_data.get("detection_method") == "llm_analysis":
            confidence_factors.append(0.8)
        elif vulnerability_data.get("detection_method") == "static_analysis":
            confidence_factors.append(0.9)
        elif vulnerability_data.get("detection_method") == "pattern_matching":
            confidence_factors.append(0.6)
            
        # Factor in severity
        severity = vulnerability_data.get("severity", "medium").lower()
        if severity == "critical":
            confidence_factors.append(0.9)
        elif severity == "high":
            confidence_factors.append(0.8)
        elif severity == "medium":
            confidence_factors.append(0.7)
        else:
            confidence_factors.append(0.5)
            
        # Calculate average confidence
        return sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.5
