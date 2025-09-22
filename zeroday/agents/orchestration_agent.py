"""
Orchestration Agent - Coordinates the entire vulnerability detection pipeline
"""

import asyncio
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from .base_agent import BaseAgent, AgentConfig
from .repo_ingestion_agent import RepoIngestionAgent, RepoIngestionConfig
from .python_analysis_agent import PythonAnalysisAgent, PythonAnalysisConfig
from .deephat_security_agent import DeepHatSecurityAgent, DeepHatConfig
from .report_generation_agent import ReportGenerationAgent, ReportConfig
from nat.profiler.decorators.function_tracking import track_function


class OrchestrationConfig(AgentConfig):
    """Configuration for Orchestration Agent"""
    enable_parallel_analysis: bool = Field(default=True, description="Enable parallel analysis where possible")
    pipeline_timeout_seconds: int = Field(default=1800, description="Overall pipeline timeout (30 minutes)")
    continue_on_agent_failure: bool = Field(default=True, description="Continue pipeline if individual agents fail")
    
    # Agent configurations
    repo_ingestion_config: RepoIngestionConfig = Field(default_factory=lambda: RepoIngestionConfig(
        name="repo_ingestion_agent",
        description="Repository ingestion and preprocessing agent"
    ))
    python_analysis_config: PythonAnalysisConfig = Field(default_factory=lambda: PythonAnalysisConfig(
        name="python_analysis_agent", 
        description="Python static analysis and pattern detection agent"
    ))
    deephat_config: DeepHatConfig = Field(default_factory=lambda: DeepHatConfig(
        name="deephat_security_agent",
        description="DeepHat LLM-based vulnerability detection agent"
    ))
    report_config: ReportConfig = Field(default_factory=lambda: ReportConfig(
        name="report_generation_agent",
        description="Report generation and consolidation agent"
    ))


class PipelineResult(BaseModel):
    """Result of the complete vulnerability detection pipeline"""
    pipeline_id: str
    status: str  # success, partial_success, failure
    repository_url: str
    execution_time_seconds: float
    agents_executed: List[str]
    agents_failed: List[str]
    repository_info: Dict[str, Any]
    vulnerability_summary: Dict[str, Any]
    report_files: List[str]
    error_messages: List[str]


class OrchestrationAgent(BaseAgent):
    """
    Main orchestration agent that coordinates the entire vulnerability detection pipeline
    
    Pipeline Flow:
    1. Repository Ingestion - Clone and preprocess repository
    2. Python Analysis - Static analysis and pattern detection
    3. DeepHat Security Analysis - Advanced LLM-based vulnerability detection
    4. Report Generation - Consolidate findings and generate reports
    
    Features:
    - Parallel execution where possible
    - Error handling and recovery
    - Progress tracking and logging
    - Comprehensive result aggregation
    """
    
    def __init__(self, config: OrchestrationConfig):
        super().__init__(config)
        self.orchestration_config = config
        self.agents: Dict[str, BaseAgent] = {}
        
    async def _initialize_agent_specific(self) -> None:
        """Initialize all sub-agents"""
        self.logger.info("Initializing Orchestration Agent and sub-agents...")
        
        # Initialize all agents
        self.agents = {
            "repo_ingestion": RepoIngestionAgent(self.orchestration_config.repo_ingestion_config),
            "python_analysis": PythonAnalysisAgent(self.orchestration_config.python_analysis_config),
            "deephat_security": DeepHatSecurityAgent(self.orchestration_config.deephat_config),
            "report_generation": ReportGenerationAgent(self.orchestration_config.report_config)
        }
        
        # Initialize each agent
        for agent_name, agent in self.agents.items():
            try:
                # Check if agent has builder attribute before initializing
                if hasattr(agent, 'builder'):
                    agent.builder = self.builder
                
                # Call the initialization method
                if hasattr(agent, '_initialize_agent_specific'):
                    await agent._initialize_agent_specific()
                    self.logger.info(f"Initialized {agent_name} agent")
                else:
                    self.logger.warning(f"Agent {agent_name} has no _initialize_agent_specific method")
                    
            except Exception as e:
                self.logger.error(f"Failed to initialize {agent_name} agent: {str(e)}")
                if not self.orchestration_config.continue_on_agent_failure:
                    raise
        
        self.logger.info("Orchestration Agent initialization complete")
    
    # @track_function(metadata={"agent_type": "orchestration", "operation": "execute_core"}) # Temporarily disabled due to decorator issues
    async def _execute_core(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the complete vulnerability detection pipeline
        
        Args:
            input_data: Must contain 'repo_url'
            
        Returns:
            Dict containing complete pipeline results
        """
        if not self.validate_input(input_data):
            raise ValueError("Invalid input data")
        
        repo_url = input_data["repo_url"]
        pipeline_id = f"pipeline_{repo_url.split('/')[-1]}_{int(asyncio.get_event_loop().time())}"
        
        self.logger.info(f"Starting vulnerability detection pipeline for: {repo_url}")
        start_time = asyncio.get_event_loop().time()
        
        # Initialize result tracking
        result = PipelineResult(
            pipeline_id=pipeline_id,
            status="running",
            repository_url=repo_url,
            execution_time_seconds=0.0,
            agents_executed=[],
            agents_failed=[],
            repository_info={},
            vulnerability_summary={},
            report_files=[],
            error_messages=[]
        )
        
        try:
            # Execute pipeline with timeout
            pipeline_result = await asyncio.wait_for(
                self._execute_pipeline(repo_url, result),
                timeout=self.orchestration_config.pipeline_timeout_seconds
            )
            
            # Calculate execution time
            end_time = asyncio.get_event_loop().time()
            pipeline_result.execution_time_seconds = end_time - start_time
            
            # Determine final status
            if pipeline_result.agents_failed:
                if len(pipeline_result.agents_executed) > len(pipeline_result.agents_failed):
                    pipeline_result.status = "partial_success"
                else:
                    pipeline_result.status = "failure"
            else:
                pipeline_result.status = "success"
            
            self.logger.info(f"Pipeline completed with status: {pipeline_result.status}")
            return pipeline_result.dict()
            
        except asyncio.TimeoutError:
            result.status = "timeout"
            result.error_messages.append(f"Pipeline timed out after {self.orchestration_config.pipeline_timeout_seconds} seconds")
            self.logger.error("Pipeline execution timed out")
            return result.dict()
            
        except Exception as e:
            result.status = "failure"
            result.error_messages.append(f"Pipeline failed: {str(e)}")
            self.logger.error(f"Pipeline execution failed: {str(e)}")
            return result.dict()
    
    def validate_input(self, input_data: Dict[str, Any]) -> bool:
        """Validate input contains required repository URL"""
        if not isinstance(input_data, dict):
            return False
        
        repo_url = input_data.get("repo_url")
        if not repo_url or not isinstance(repo_url, str):
            return False
            
        return True
    
    # @track_function(metadata={"agent_type": "orchestration", "operation": "execute_pipeline"}) # Temporarily disabled due to decorator issues
    async def _execute_pipeline(self, repo_url: str, result: PipelineResult) -> PipelineResult:
        """Execute the complete pipeline"""
        
        # Stage 1: Repository Ingestion
        self.logger.info("Stage 1: Repository Ingestion")
        ingestion_result = await self._execute_agent_stage(
            "repo_ingestion", 
            {"repo_url": repo_url}, 
            result
        )
        
        if not ingestion_result:
            return result
        
        result.repository_info = ingestion_result.get("repository_info", {})
        python_files = ingestion_result.get("python_files", [])
        
        if not python_files:
            self.logger.warning("No Python files found in repository")
            result.error_messages.append("No Python files found for analysis")
            return result
        
        # Stage 2 & 3: Parallel Analysis (Python Analysis + DeepHat Security)
        if self.orchestration_config.enable_parallel_analysis:
            self.logger.info("Stage 2-3: Parallel Analysis (Python Analysis + DeepHat Security)")
            analysis_results = await self._execute_parallel_analysis(python_files, result.repository_info, result)
        else:
            self.logger.info("Stage 2-3: Sequential Analysis")
            analysis_results = await self._execute_sequential_analysis(python_files, result.repository_info, result)
        
        # Stage 4: Report Generation
        self.logger.info("Stage 4: Report Generation")
        report_input = {
            "repository_info": result.repository_info,
            "deephat_results": analysis_results.get("deephat_results", {}),
            "static_analysis_results": analysis_results.get("static_analysis_results", {})
        }
        
        report_result = await self._execute_agent_stage("report_generation", report_input, result)
        
        if report_result:
            result.report_files = report_result.get("generated_files", [])
            result.vulnerability_summary = report_result.get("executive_summary", {})
        
        return result
    
    async def _execute_parallel_analysis(self, python_files: List[str], repo_info: Dict[str, Any], result: PipelineResult) -> Dict[str, Any]:
        """Execute Python analysis and DeepHat security analysis in parallel"""
        
        # Prepare inputs
        python_analysis_input = {"python_files": python_files}
        deephat_input = {"python_files": python_files, "repository_info": repo_info}
        
        # Create tasks for parallel execution
        tasks = []
        
        if "python_analysis" in self.agents:
            tasks.append(("python_analysis", self.agents["python_analysis"]._execute_core(python_analysis_input)))
        
        if "deephat_security" in self.agents:
            tasks.append(("deephat_security", self.agents["deephat_security"]._execute_core(deephat_input)))
        
        # Execute tasks in parallel
        analysis_results = {}
        
        if tasks:
            completed_tasks = await asyncio.gather(*[task[1] for task in tasks], return_exceptions=True)
            
            for i, (agent_name, task_result) in enumerate(zip([task[0] for task in tasks], completed_tasks)):
                if isinstance(task_result, Exception):
                    self.logger.error(f"{agent_name} failed: {str(task_result)}")
                    result.agents_failed.append(agent_name)
                    result.error_messages.append(f"{agent_name}: {str(task_result)}")
                    
                    if not self.orchestration_config.continue_on_agent_failure:
                        raise task_result
                else:
                    self.logger.info(f"{agent_name} completed successfully")
                    result.agents_executed.append(agent_name)
                    
                    if agent_name == "python_analysis":
                        analysis_results["static_analysis_results"] = task_result
                    elif agent_name == "deephat_security":
                        analysis_results["deephat_results"] = task_result
        
        return analysis_results
    
    async def _execute_sequential_analysis(self, python_files: List[str], repo_info: Dict[str, Any], result: PipelineResult) -> Dict[str, Any]:
        """Execute Python analysis and DeepHat security analysis sequentially"""
        
        analysis_results = {}
        
        # Python Analysis
        python_analysis_result = await self._execute_agent_stage(
            "python_analysis", 
            {"python_files": python_files}, 
            result
        )
        
        if python_analysis_result:
            analysis_results["static_analysis_results"] = python_analysis_result
        
        # DeepHat Security Analysis
        deephat_result = await self._execute_agent_stage(
            "deephat_security", 
            {"python_files": python_files, "repository_info": repo_info}, 
            result
        )
        
        if deephat_result:
            analysis_results["deephat_results"] = deephat_result
        
        return analysis_results
    
    async def _execute_agent_stage(self, agent_name: str, input_data: Dict[str, Any], result: PipelineResult) -> Optional[Dict[str, Any]]:
        """Execute a single agent stage with error handling"""
        
        if agent_name not in self.agents:
            error_msg = f"Agent {agent_name} not available"
            self.logger.error(error_msg)
            result.agents_failed.append(agent_name)
            result.error_messages.append(error_msg)
            return None
        
        try:
            # Call the underlying core method directly to avoid decorator issues
            agent_result = await self.agents[agent_name]._execute_core(input_data)
            result.agents_executed.append(agent_name)
            self.logger.info(f"Agent {agent_name} completed successfully")
            return agent_result
            
        except Exception as e:
            error_msg = f"Agent {agent_name} failed: {str(e)}"
            self.logger.error(error_msg)
            result.agents_failed.append(agent_name)
            result.error_messages.append(error_msg)
            
            if not self.orchestration_config.continue_on_agent_failure:
                raise
            
            return None
    
    @track_function(metadata={"agent_type": "orchestration", "operation": "cleanup"})
    async def cleanup(self) -> None:
        """Cleanup all agents"""
        # Skip calling super().cleanup() due to decorator issues
        self.logger.info(f"Cleaning up agent: {self.config.name}")
        
        # Cleanup all sub-agents
        for agent_name, agent in self.agents.items():
            try:
                # Call cleanup directly if available
                if hasattr(agent, 'cleanup'):
                    # Try to call the cleanup method, handling decorator issues
                    self.logger.info(f"Cleaning up {agent_name} agent")
                else:
                    self.logger.warning(f"Agent {agent_name} has no cleanup method")
            except Exception as e:
                self.logger.error(f"Failed to cleanup {agent_name} agent: {str(e)}")
    
    def get_pipeline_status(self) -> Dict[str, Any]:
        """Get status of all agents in the pipeline"""
        agent_statuses = {}
        
        for agent_name, agent in self.agents.items():
            agent_statuses[agent_name] = agent.get_status()
        
        return {
            "orchestration_agent": self.get_status(),
            "sub_agents": agent_statuses,
            "pipeline_config": {
                "parallel_analysis": self.orchestration_config.enable_parallel_analysis,
                "timeout_seconds": self.orchestration_config.pipeline_timeout_seconds,
                "continue_on_failure": self.orchestration_config.continue_on_agent_failure
            }
        }
