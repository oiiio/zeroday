#!/usr/bin/env python3
"""
ZeroDay Pipeline - Repository Analysis Script

Simple script to analyze a repository for vulnerabilities using the ZeroDay pipeline.
"""

import asyncio
import argparse
import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from zeroday.agents.orchestration_agent import OrchestrationAgent, OrchestrationConfig
from zeroday.agents.repo_ingestion_agent import RepoIngestionConfig
from zeroday.agents.python_analysis_agent import PythonAnalysisConfig
from zeroday.agents.deephat_security_agent import DeepHatConfig
from zeroday.agents.report_generation_agent import ReportConfig


async def analyze_repository(repo_url: str, output_dir: str = "./data/reports") -> dict:
    """
    Analyze a repository for vulnerabilities
    
    Args:
        repo_url: URL of the repository to analyze
        output_dir: Directory to save reports
        
    Returns:
        Analysis results
    """
    print(f"🔍 Starting vulnerability analysis for: {repo_url}")
    
    # Configure agents
    orchestration_config = OrchestrationConfig(
        name="zeroday_orchestrator",
        description="ZeroDay vulnerability detection orchestrator",
        enable_parallel_analysis=True,
        pipeline_timeout_seconds=1800,  # 30 minutes
        continue_on_agent_failure=True,
        
        # Agent-specific configurations
        repo_ingestion_config=RepoIngestionConfig(
            name="repo_ingestion",
            description="Repository ingestion and preprocessing",
            max_repo_size_mb=500,
            temp_dir="./data/repositories"
        ),
        
        python_analysis_config=PythonAnalysisConfig(
            name="python_analysis", 
            description="Python static analysis and pattern detection",
            enable_ast_analysis=True,
            enable_pattern_matching=True
        ),
        
        deephat_config=DeepHatConfig(
            name="deephat_security",
            description="DeepHat-powered vulnerability detection",
            model_name="DeepHat/DeepHat-V1-7B",
            device="auto",
            torch_dtype="auto",
            max_context_length=32768,
            temperature=0.1,
            enable_zero_day_detection=True
        ),
        
        report_config=ReportConfig(
            name="report_generation",
            description="Vulnerability report generation",
            output_dir=output_dir,
            report_formats=["json", "html", "txt"],
            include_code_snippets=True
        )
    )
    
    # Create orchestration agent
    orchestration_agent = OrchestrationAgent(orchestration_config)
    
    try:
        # Initialize the orchestration agent manually (bypassing NeMo for now)
        print("🚀 Initializing agents...")
        orchestration_agent.builder = None  # Set builder to None for now
        await orchestration_agent._initialize_agent_specific()
        
        # Execute pipeline
        print("⚙️ Executing vulnerability detection pipeline...")
        result = await orchestration_agent.execute({"repo_url": repo_url})
        
        return result
        
    except Exception as e:
        print(f"❌ Pipeline execution failed: {str(e)}")
        return {
            "status": "error",
            "error_message": str(e),
            "repository_url": repo_url
        }
    
    finally:
        # Cleanup
        try:
            await orchestration_agent.cleanup()
        except:
            pass


def print_results(result: dict) -> None:
    """Print analysis results in a formatted way"""
    
    print("\n" + "="*60)
    print("🔒 VULNERABILITY ANALYSIS RESULTS")
    print("="*60)
    
    status = result.get("status", "unknown")
    repo_url = result.get("repository_url", "unknown")
    
    print(f"Repository: {repo_url}")
    print(f"Status: {status.upper()}")
    
    if status == "error":
        print(f"Error: {result.get('error_message', 'Unknown error')}")
        return
    
    # Pipeline execution info
    execution_time = result.get("execution_time_seconds", 0)
    agents_executed = result.get("agents_executed", [])
    agents_failed = result.get("agents_failed", [])
    
    print(f"Execution Time: {execution_time:.2f} seconds")
    print(f"Agents Executed: {', '.join(agents_executed)}")
    
    if agents_failed:
        print(f"Agents Failed: {', '.join(agents_failed)}")
    
    # Vulnerability summary
    vuln_summary = result.get("vulnerability_summary", {})
    if vuln_summary:
        print(f"\n📊 VULNERABILITY SUMMARY")
        print(f"Total Vulnerabilities: {vuln_summary.get('total_vulnerabilities', 0)}")
        print(f"Overall Risk: {vuln_summary.get('overall_risk', 'Unknown')}")
        
        severity_breakdown = vuln_summary.get('severity_breakdown', {})
        if severity_breakdown:
            print("Severity Breakdown:")
            for severity, count in severity_breakdown.items():
                if count > 0:
                    print(f"  {severity.title()}: {count}")
    
    # Report files
    report_files = result.get("report_files", [])
    if report_files:
        print(f"\n📄 GENERATED REPORTS")
        for report_file in report_files:
            print(f"  {report_file}")
    
    # Error messages
    error_messages = result.get("error_messages", [])
    if error_messages:
        print(f"\n⚠️ WARNINGS/ERRORS")
        for error in error_messages:
            print(f"  {error}")
    
    print("\n" + "="*60)


async def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Analyze a repository for zero-day vulnerabilities using the ZeroDay pipeline"
    )
    
    parser.add_argument(
        "repo_url",
        help="URL of the repository to analyze (e.g., https://github.com/user/repo)"
    )
    
    parser.add_argument(
        "--output-dir",
        default="./data/reports",
        help="Directory to save reports (default: ./data/reports)"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Validate repository URL
    if not args.repo_url.startswith(("http://", "https://")):
        print("❌ Error: Repository URL must start with http:// or https://")
        sys.exit(1)
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Run analysis
    try:
        result = await analyze_repository(args.repo_url, args.output_dir)
        print_results(result)
        
        # Exit with appropriate code
        status = result.get("status", "error")
        if status == "success":
            print("✅ Analysis completed successfully!")
            sys.exit(0)
        elif status == "partial_success":
            print("⚠️ Analysis completed with some issues.")
            sys.exit(1)
        else:
            print("❌ Analysis failed.")
            sys.exit(2)
            
    except KeyboardInterrupt:
        print("\n🛑 Analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())
