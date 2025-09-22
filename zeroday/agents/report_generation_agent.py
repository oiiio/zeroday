"""
Report Generation Agent - Consolidates findings and generates comprehensive vulnerability reports
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from .base_agent import BaseAgent, AgentConfig
from nat.profiler.decorators.function_tracking import track_function


class ReportConfig(AgentConfig):
    """Configuration for Report Generation Agent"""
    output_dir: str = Field(default="./data/reports", description="Directory for generated reports")
    report_formats: List[str] = Field(default=["json", "html", "txt"], description="Report formats to generate")
    include_code_snippets: bool = Field(default=True, description="Include code snippets in reports")
    max_snippet_length: int = Field(default=500, description="Maximum length of code snippets")
    severity_colors: Dict[str, str] = Field(
        default={
            "critical": "#FF0000",
            "high": "#FF6600", 
            "medium": "#FFAA00",
            "low": "#00AA00"
        },
        description="Color codes for severity levels"
    )


class VulnerabilityReport(BaseModel):
    """Comprehensive vulnerability report"""
    report_id: str
    timestamp: str
    repository_info: Dict[str, Any]
    executive_summary: Dict[str, Any]
    vulnerability_findings: List[Dict[str, Any]]
    static_analysis_results: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    recommendations: List[str]
    metadata: Dict[str, Any]


class ReportGenerationAgent(BaseAgent):
    """
    Agent responsible for generating comprehensive vulnerability reports
    
    Capabilities:
    - Consolidate findings from multiple analysis agents
    - Generate reports in multiple formats (JSON, HTML, TXT)
    - Create executive summaries
    - Provide risk assessments and recommendations
    - Generate visualizations and charts
    """
    
    def __init__(self, config: ReportConfig):
        super().__init__(config)
        self.report_config = config
        self._ensure_output_dir()
        
    def _ensure_output_dir(self) -> None:
        """Ensure output directory exists"""
        os.makedirs(self.report_config.output_dir, exist_ok=True)
    
    async def _initialize_agent_specific(self) -> None:
        """Initialize report generation specific components"""
        self.logger.info("Report Generation Agent initialized")
    
    @track_function(metadata={"agent_type": "report_generation", "operation": "execute_core"})
    async def _execute_core(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Core execution logic for report generation
        
        Args:
            input_data: Must contain analysis results from various agents
            
        Returns:
            Dict containing report generation results
        """
        if not self.validate_input(input_data):
            raise ValueError("Invalid input data")
        
        self.logger.info("Starting vulnerability report generation")
        
        # Generate comprehensive report
        report = await self._generate_comprehensive_report(input_data)
        
        # Save reports in different formats
        report_files = await self._save_reports(report)
        
        return {
            "status": "success",
            "report_id": report.report_id,
            "generated_files": report_files,
            "executive_summary": report.executive_summary,
            "total_vulnerabilities": len(report.vulnerability_findings),
            "risk_level": report.risk_assessment.get("overall_risk", "unknown")
        }
    
    def validate_input(self, input_data: Dict[str, Any]) -> bool:
        """Validate input contains required analysis results"""
        if not isinstance(input_data, dict):
            return False
        
        # Check for required components
        required_keys = ["repository_info"]
        for key in required_keys:
            if key not in input_data:
                return False
                
        return True
    
    @track_function(metadata={"agent_type": "report_generation", "operation": "generate_report"})
    async def _generate_comprehensive_report(self, input_data: Dict[str, Any]) -> VulnerabilityReport:
        """Generate comprehensive vulnerability report"""
        
        # Generate unique report ID
        report_id = f"vuln_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Extract data from input
        repo_info = input_data.get("repository_info", {})
        deephat_results = input_data.get("deephat_results", {})
        static_analysis_results = input_data.get("static_analysis_results", {})
        
        # Consolidate vulnerability findings
        vulnerability_findings = self._consolidate_vulnerability_findings(deephat_results, static_analysis_results)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(vulnerability_findings, repo_info)
        
        # Perform risk assessment
        risk_assessment = self._perform_risk_assessment(vulnerability_findings)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(vulnerability_findings, risk_assessment)
        
        # Create report
        report = VulnerabilityReport(
            report_id=report_id,
            timestamp=datetime.now().isoformat(),
            repository_info=repo_info,
            executive_summary=executive_summary,
            vulnerability_findings=vulnerability_findings,
            static_analysis_results=static_analysis_results,
            risk_assessment=risk_assessment,
            recommendations=recommendations,
            metadata={
                "generator": "ZeroDay Pipeline",
                "version": "0.1.0",
                "analysis_agents": ["DeepHat Security Agent", "Python Analysis Agent"]
            }
        )
        
        return report
    
    def _consolidate_vulnerability_findings(self, deephat_results: Dict[str, Any], static_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Consolidate vulnerability findings from different agents"""
        consolidated_findings = []
        
        # Add DeepHat findings
        if deephat_results and "vulnerabilities" in deephat_results:
            for vuln in deephat_results["vulnerabilities"]:
                vuln["source"] = "DeepHat Analysis"
                consolidated_findings.append(vuln)
        
        # Add static analysis findings (convert to vulnerability format)
        if static_results and "analysis_results" in static_results:
            for result in static_results["analysis_results"]:
                # Convert dangerous calls to vulnerabilities
                for call in result.get("dangerous_calls", []):
                    vuln = {
                        "file_path": result["file_path"],
                        "line_number": call.get("line"),
                        "vulnerability_type": "dangerous_function_call",
                        "severity": "medium",
                        "confidence": 0.8,
                        "description": f"Potentially dangerous function call: {call.get('function')}",
                        "detection_method": "static_analysis",
                        "source": "Python Analysis Agent"
                    }
                    consolidated_findings.append(vuln)
                
                # Convert suspicious patterns to vulnerabilities
                for pattern in result.get("suspicious_patterns", []):
                    vuln = {
                        "file_path": result["file_path"],
                        "line_number": pattern.get("line"),
                        "vulnerability_type": "suspicious_pattern",
                        "severity": "low",
                        "confidence": 0.6,
                        "description": f"Suspicious code pattern detected: {pattern.get('match', '')[:100]}",
                        "detection_method": "pattern_matching",
                        "source": "Python Analysis Agent"
                    }
                    consolidated_findings.append(vuln)
        
        # Sort by severity and confidence
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        consolidated_findings.sort(
            key=lambda x: (severity_order.get(x.get("severity", "low"), 3), -x.get("confidence", 0))
        )
        
        return consolidated_findings
    
    def _generate_executive_summary(self, findings: List[Dict[str, Any]], repo_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of findings"""
        total_vulnerabilities = len(findings)
        
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            severity = finding.get("severity", "low")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count by type
        type_counts = {}
        for finding in findings:
            vuln_type = finding.get("vulnerability_type", "unknown")
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        # Determine overall risk
        if severity_counts["critical"] > 0:
            overall_risk = "Critical"
        elif severity_counts["high"] > 0:
            overall_risk = "High"
        elif severity_counts["medium"] > 0:
            overall_risk = "Medium"
        else:
            overall_risk = "Low"
        
        return {
            "repository_name": repo_info.get("name", "Unknown"),
            "repository_url": repo_info.get("url", ""),
            "total_vulnerabilities": total_vulnerabilities,
            "severity_breakdown": severity_counts,
            "vulnerability_types": type_counts,
            "overall_risk": overall_risk,
            "files_analyzed": len(set(f.get("file_path", "") for f in findings)),
            "zero_day_potential": sum(f.get("zero_day_likelihood", 0) for f in findings) / max(len(findings), 1)
        }
    
    def _perform_risk_assessment(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform comprehensive risk assessment"""
        if not findings:
            return {"overall_risk": "Low", "risk_score": 0}
        
        # Calculate risk score
        risk_score = 0
        for finding in findings:
            severity = finding.get("severity", "low")
            confidence = finding.get("confidence", 0.5)
            
            # Severity weights
            severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
            risk_score += severity_weights.get(severity, 1) * confidence
        
        # Normalize risk score
        max_possible_score = len(findings) * 10
        normalized_score = (risk_score / max_possible_score) * 100 if max_possible_score > 0 else 0
        
        # Determine risk level
        if normalized_score >= 70:
            risk_level = "Critical"
        elif normalized_score >= 50:
            risk_level = "High"
        elif normalized_score >= 30:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        return {
            "overall_risk": risk_level,
            "risk_score": round(normalized_score, 2),
            "total_findings": len(findings),
            "high_confidence_findings": len([f for f in findings if f.get("confidence", 0) >= 0.8]),
            "zero_day_indicators": len([f for f in findings if f.get("zero_day_likelihood", 0) > 0.5])
        }
    
    def _generate_recommendations(self, findings: List[Dict[str, Any]], risk_assessment: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # General recommendations based on risk level
        risk_level = risk_assessment.get("overall_risk", "Low")
        
        if risk_level in ["Critical", "High"]:
            recommendations.append("🚨 URGENT: Address critical and high-severity vulnerabilities immediately")
            recommendations.append("🔒 Implement additional security controls and monitoring")
            recommendations.append("🧪 Conduct thorough security testing before deployment")
        
        # Specific recommendations based on vulnerability types
        vuln_types = set(f.get("vulnerability_type", "") for f in findings)
        
        if "sql_injection" in vuln_types:
            recommendations.append("🛡️ Use parameterized queries and prepared statements to prevent SQL injection")
        
        if "command_injection" in vuln_types:
            recommendations.append("⚡ Validate and sanitize all user inputs before executing system commands")
        
        if "hardcoded_credentials" in vuln_types:
            recommendations.append("🔑 Remove hardcoded credentials and use secure credential management")
        
        if "dangerous_function_call" in vuln_types:
            recommendations.append("⚠️ Review and secure usage of potentially dangerous functions")
        
        if any(f.get("zero_day_likelihood", 0) > 0.5 for f in findings):
            recommendations.append("🔍 Investigate potential zero-day vulnerabilities with security experts")
        
        # General security recommendations
        recommendations.extend([
            "📚 Conduct regular security code reviews",
            "🔄 Keep dependencies updated to latest secure versions",
            "🧪 Implement automated security testing in CI/CD pipeline",
            "📊 Monitor application for suspicious activities",
            "🎓 Provide security training for development team"
        ])
        
        return recommendations
    
    @track_function(metadata={"agent_type": "report_generation", "operation": "save_reports"})
    async def _save_reports(self, report: VulnerabilityReport) -> List[str]:
        """Save reports in different formats"""
        generated_files = []
        
        for format_type in self.report_config.report_formats:
            try:
                if format_type == "json":
                    file_path = await self._save_json_report(report)
                elif format_type == "html":
                    file_path = await self._save_html_report(report)
                elif format_type == "txt":
                    file_path = await self._save_text_report(report)
                else:
                    self.logger.warning(f"Unsupported report format: {format_type}")
                    continue
                
                generated_files.append(file_path)
                self.logger.info(f"Generated {format_type.upper()} report: {file_path}")
                
            except Exception as e:
                self.logger.error(f"Failed to generate {format_type} report: {str(e)}")
        
        return generated_files
    
    async def _save_json_report(self, report: VulnerabilityReport) -> str:
        """Save report as JSON"""
        file_path = os.path.join(self.report_config.output_dir, f"{report.report_id}.json")
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report.dict(), f, indent=2, ensure_ascii=False)
        
        return file_path
    
    async def _save_html_report(self, report: VulnerabilityReport) -> str:
        """Save report as HTML"""
        file_path = os.path.join(self.report_config.output_dir, f"{report.report_id}.html")
        
        html_content = self._generate_html_content(report)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return file_path
    
    async def _save_text_report(self, report: VulnerabilityReport) -> str:
        """Save report as plain text"""
        file_path = os.path.join(self.report_config.output_dir, f"{report.report_id}.txt")
        
        text_content = self._generate_text_content(report)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(text_content)
        
        return file_path
    
    def _generate_html_content(self, report: VulnerabilityReport) -> str:
        """Generate HTML content for the report"""
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Report - {report.report_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; }}
        .summary {{ background-color: #e9ecef; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid {self.report_config.severity_colors['critical']}; }}
        .high {{ border-left: 5px solid {self.report_config.severity_colors['high']}; }}
        .medium {{ border-left: 5px solid {self.report_config.severity_colors['medium']}; }}
        .low {{ border-left: 5px solid {self.report_config.severity_colors['low']}; }}
        .code {{ background-color: #f8f9fa; padding: 10px; font-family: monospace; border-radius: 3px; }}
        .recommendations {{ background-color: #d4edda; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Vulnerability Assessment Report</h1>
        <p><strong>Report ID:</strong> {report.report_id}</p>
        <p><strong>Generated:</strong> {report.timestamp}</p>
        <p><strong>Repository:</strong> {report.repository_info.get('name', 'Unknown')}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Executive Summary</h2>
        <p><strong>Overall Risk Level:</strong> {report.executive_summary.get('overall_risk', 'Unknown')}</p>
        <p><strong>Total Vulnerabilities:</strong> {report.executive_summary.get('total_vulnerabilities', 0)}</p>
        <p><strong>Files Analyzed:</strong> {report.executive_summary.get('files_analyzed', 0)}</p>
        
        <h3>Severity Breakdown:</h3>
        <ul>
"""
        
        severity_breakdown = report.executive_summary.get('severity_breakdown', {})
        for severity, count in severity_breakdown.items():
            if count > 0:
                html += f"<li><strong>{severity.title()}:</strong> {count}</li>"
        
        html += """
        </ul>
    </div>
    
    <div>
        <h2>🚨 Vulnerability Findings</h2>
"""
        
        for vuln in report.vulnerability_findings:
            severity = vuln.get('severity', 'low')
            html += f"""
        <div class="vulnerability {severity}">
            <h3>{vuln.get('vulnerability_type', 'Unknown').replace('_', ' ').title()}</h3>
            <p><strong>File:</strong> {vuln.get('file_path', 'Unknown')}</p>
            <p><strong>Severity:</strong> {severity.title()}</p>
            <p><strong>Confidence:</strong> {vuln.get('confidence', 0):.2f}</p>
            <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
"""
            
            if vuln.get('code_snippet') and self.report_config.include_code_snippets:
                snippet = vuln['code_snippet'][:self.report_config.max_snippet_length]
                html += f'<div class="code">{snippet}</div>'
            
            if vuln.get('recommendation'):
                html += f"<p><strong>Recommendation:</strong> {vuln['recommendation']}</p>"
            
            html += "</div>"
        
        html += """
    </div>
    
    <div class="recommendations">
        <h2>💡 Recommendations</h2>
        <ul>
"""
        
        for rec in report.recommendations:
            html += f"<li>{rec}</li>"
        
        html += """
        </ul>
    </div>
</body>
</html>
"""
        
        return html
    
    def _generate_text_content(self, report: VulnerabilityReport) -> str:
        """Generate plain text content for the report"""
        content = f"""
🔒 VULNERABILITY ASSESSMENT REPORT
{'=' * 50}

Report ID: {report.report_id}
Generated: {report.timestamp}
Repository: {report.repository_info.get('name', 'Unknown')}
URL: {report.repository_info.get('url', 'N/A')}

📊 EXECUTIVE SUMMARY
{'-' * 20}
Overall Risk Level: {report.executive_summary.get('overall_risk', 'Unknown')}
Total Vulnerabilities: {report.executive_summary.get('total_vulnerabilities', 0)}
Files Analyzed: {report.executive_summary.get('files_analyzed', 0)}

Severity Breakdown:
"""
        
        severity_breakdown = report.executive_summary.get('severity_breakdown', {})
        for severity, count in severity_breakdown.items():
            if count > 0:
                content += f"  {severity.title()}: {count}\n"
        
        content += f"\n🚨 VULNERABILITY FINDINGS\n{'-' * 25}\n"
        
        for i, vuln in enumerate(report.vulnerability_findings, 1):
            content += f"""
{i}. {vuln.get('vulnerability_type', 'Unknown').replace('_', ' ').title()}
   File: {vuln.get('file_path', 'Unknown')}
   Line: {vuln.get('line_number', 'N/A')}
   Severity: {vuln.get('severity', 'Unknown').title()}
   Confidence: {vuln.get('confidence', 0):.2f}
   Description: {vuln.get('description', 'No description available')}
"""
            
            if vuln.get('recommendation'):
                content += f"   Recommendation: {vuln['recommendation']}\n"
        
        content += f"\n💡 RECOMMENDATIONS\n{'-' * 18}\n"
        
        for i, rec in enumerate(report.recommendations, 1):
            content += f"{i}. {rec}\n"
        
        content += f"\n📈 RISK ASSESSMENT\n{'-' * 17}\n"
        risk_assessment = report.risk_assessment
        content += f"Risk Score: {risk_assessment.get('risk_score', 0)}/100\n"
        content += f"High Confidence Findings: {risk_assessment.get('high_confidence_findings', 0)}\n"
        content += f"Zero-day Indicators: {risk_assessment.get('zero_day_indicators', 0)}\n"
        
        return content
