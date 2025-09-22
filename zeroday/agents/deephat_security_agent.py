"""
DeepHat Security Agent - Integrates DeepHat-V1-7B model for advanced vulnerability detection
"""

import os
import json
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from .base_agent import SecurityBaseAgent, SecurityAgentConfig
from nat.profiler.decorators.function_tracking import track_function


class DeepHatConfig(SecurityAgentConfig):
    """Configuration for DeepHat Security Agent"""
    model_name: str = Field(default="DeepHat/DeepHat-V1-7B", description="DeepHat model name")
    model_path: Optional[str] = Field(default=None, description="Local model path if downloaded")
    device: str = Field(default="auto", description="Device to run model on (auto, cuda, cpu)")
    torch_dtype: str = Field(default="auto", description="Torch dtype (auto, float16, bfloat16)")
    max_context_length: int = Field(default=32768, description="Maximum context length for analysis")
    temperature: float = Field(default=0.1, description="Temperature for model generation")
    max_new_tokens: int = Field(default=2048, description="Maximum new tokens to generate")
    vulnerability_types: List[str] = Field(
        default=[
            "code_injection",
            "sql_injection", 
            "command_injection",
            "authentication_bypass",
            "authorization_bypass",
            "cryptographic_weakness",
            "deserialization_vulnerability",
            "path_traversal",
            "xss",
            "csrf",
            "hardcoded_credentials",
            "insecure_random",
            "buffer_overflow",
            "race_condition",
            "zero_day_pattern"
        ],
        description="Types of vulnerabilities to detect"
    )


class VulnerabilityFinding(BaseModel):
    """Represents a vulnerability finding"""
    file_path: str
    line_number: Optional[int] = None
    vulnerability_type: str
    severity: str  # critical, high, medium, low
    confidence: float  # 0.0 to 1.0
    description: str
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None
    detection_method: str = "llm_analysis"
    zero_day_likelihood: float = 0.0


class DeepHatSecurityAgent(SecurityBaseAgent):
    """
    Agent that uses DeepHat-V1-7B model for advanced vulnerability detection
    
    Capabilities:
    - Advanced code analysis using DeepHat LLM
    - Zero-day vulnerability pattern detection
    - Context-aware security analysis
    - Multi-layered vulnerability assessment
    """
    
    def __init__(self, config: DeepHatConfig):
        super().__init__(config)
        self.deephat_config = config
        self.model = None
        self.tokenizer = None
        
    async def _initialize_agent_specific(self) -> None:
        """Initialize DeepHat model and tokenizer"""
        self.logger.info("Initializing DeepHat Security Agent...")
        await self._load_deephat_model()
        self.logger.info("DeepHat Security Agent initialized successfully")
    
    @track_function(metadata={"agent_type": "deephat_security", "operation": "load_model"})
    async def _load_deephat_model(self) -> None:
        """Load DeepHat model and tokenizer"""
        try:
            # Import transformers here to avoid import errors if not installed
            from transformers import AutoModelForCausalLM, AutoTokenizer
            import torch
            
            model_name_or_path = self.deephat_config.model_path or self.deephat_config.model_name
            
            self.logger.info(f"Loading DeepHat model: {model_name_or_path}")
            
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(model_name_or_path)
            
            # Load model with appropriate settings
            self.model = AutoModelForCausalLM.from_pretrained(
                model_name_or_path,
                torch_dtype=self._get_torch_dtype(),
                device_map=self.deephat_config.device,
                trust_remote_code=True
            )
            
            self.logger.info("DeepHat model loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to load DeepHat model: {str(e)}")
            raise
    
    def _get_torch_dtype(self):
        """Get appropriate torch dtype"""
        import torch
        
        if self.deephat_config.torch_dtype == "float16":
            return torch.float16
        elif self.deephat_config.torch_dtype == "bfloat16":
            return torch.bfloat16
        else:
            return "auto"
    
    @track_function(metadata={"agent_type": "deephat_security", "operation": "execute_core"})
    async def _execute_core(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Core execution logic for DeepHat security analysis
        
        Args:
            input_data: Must contain 'python_files' and 'repository_info'
            
        Returns:
            Dict containing vulnerability findings
        """
        if not self.validate_input(input_data):
            raise ValueError("Invalid input data")
        
        python_files = input_data["python_files"]
        repo_info = input_data.get("repository_info", {})
        
        self.logger.info(f"Starting DeepHat analysis of {len(python_files)} Python files")
        
        # Filter files that can be analyzed
        analyzable_files = self.filter_analyzable_files(python_files)
        self.logger.info(f"Analyzing {len(analyzable_files)} files within size limits")
        
        # Analyze files for vulnerabilities
        all_findings = []
        for file_path in analyzable_files:
            try:
                findings = await self._analyze_file(file_path, repo_info)
                all_findings.extend(findings)
            except Exception as e:
                self.logger.error(f"Failed to analyze {file_path}: {str(e)}")
        
        # Filter findings by confidence threshold
        high_confidence_findings = [
            f for f in all_findings 
            if f.confidence >= self.security_config.vulnerability_confidence_threshold
        ]
        
        self.logger.info(f"Found {len(high_confidence_findings)} high-confidence vulnerabilities out of {len(all_findings)} total findings")
        
        return {
            "status": "success",
            "total_findings": len(all_findings),
            "high_confidence_findings": len(high_confidence_findings),
            "vulnerabilities": [f.dict() for f in high_confidence_findings],
            "all_findings": [f.dict() for f in all_findings],
            "analysis_summary": self._generate_analysis_summary(high_confidence_findings)
        }
    
    def validate_input(self, input_data: Dict[str, Any]) -> bool:
        """Validate input contains required data"""
        if not isinstance(input_data, dict):
            return False
        
        python_files = input_data.get("python_files")
        if not python_files or not isinstance(python_files, list):
            return False
            
        return True
    
    @track_function(metadata={"agent_type": "deephat_security", "operation": "analyze_file"})
    async def _analyze_file(self, file_path: str, repo_info: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Analyze a single Python file for vulnerabilities"""
        findings = []
        
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()
            
            if not code_content.strip():
                return findings
            
            # Truncate if too long for context window
            if len(code_content) > self.deephat_config.max_context_length * 3:  # Rough token estimation
                code_content = code_content[:self.deephat_config.max_context_length * 3]
                self.logger.warning(f"Truncated {file_path} due to length")
            
            # Perform multi-layered analysis
            findings.extend(await self._perform_comprehensive_analysis(file_path, code_content, repo_info))
            
            # Perform zero-day pattern detection if enabled
            if self.security_config.enable_zero_day_detection:
                zero_day_findings = await self._detect_zero_day_patterns(file_path, code_content, repo_info)
                findings.extend(zero_day_findings)
            
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {str(e)}")
        
        return findings
    
    @track_function(metadata={"agent_type": "deephat_security", "operation": "comprehensive_analysis"})
    async def _perform_comprehensive_analysis(self, file_path: str, code_content: str, repo_info: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Perform comprehensive vulnerability analysis using DeepHat"""
        findings = []
        
        # Create analysis prompt
        analysis_prompt = self._create_analysis_prompt(file_path, code_content, repo_info)
        
        try:
            # Generate analysis using DeepHat
            response = await self._generate_deephat_response(analysis_prompt)
            
            # Parse response to extract vulnerabilities
            parsed_findings = self._parse_vulnerability_response(response, file_path, code_content)
            findings.extend(parsed_findings)
            
        except Exception as e:
            self.logger.error(f"Error in comprehensive analysis for {file_path}: {str(e)}")
        
        return findings
    
    @track_function(metadata={"agent_type": "deephat_security", "operation": "zero_day_detection"})
    async def _detect_zero_day_patterns(self, file_path: str, code_content: str, repo_info: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Detect potential zero-day vulnerability patterns"""
        findings = []
        
        # Create zero-day detection prompt
        zero_day_prompt = self._create_zero_day_prompt(file_path, code_content, repo_info)
        
        try:
            # Generate zero-day analysis
            response = await self._generate_deephat_response(zero_day_prompt)
            
            # Parse zero-day findings
            zero_day_findings = self._parse_zero_day_response(response, file_path, code_content)
            findings.extend(zero_day_findings)
            
        except Exception as e:
            self.logger.error(f"Error in zero-day detection for {file_path}: {str(e)}")
        
        return findings
    
    def _create_analysis_prompt(self, file_path: str, code_content: str, repo_info: Dict[str, Any]) -> str:
        """Create comprehensive analysis prompt for DeepHat"""
        repo_context = ""
        if repo_info:
            dependencies = repo_info.get("dependencies", [])
            if dependencies:
                repo_context = f"\n\nRepository dependencies: {', '.join(dependencies[:10])}"
        
        prompt = f"""You are DeepHat, a cybersecurity expert analyzing Python code for vulnerabilities. 

Analyze the following Python file for security vulnerabilities:

File: {file_path}
{repo_context}

Code:
```python
{code_content}
```

Please identify any security vulnerabilities in this code. For each vulnerability found, provide:

1. Vulnerability type (e.g., SQL injection, command injection, authentication bypass, etc.)
2. Severity level (critical, high, medium, low)
3. Line number (if applicable)
4. Description of the vulnerability
5. Code snippet showing the vulnerable code
6. Recommendation for fixing the vulnerability
7. CWE ID if applicable
8. Confidence level (0.0 to 1.0)

Focus on:
- Code injection vulnerabilities (SQL, command, template injection)
- Authentication and authorization bypasses
- Cryptographic weaknesses
- Unsafe deserialization
- Hard-coded credentials
- Path traversal vulnerabilities
- Input validation issues
- Race conditions
- Buffer overflows (in C extensions)

Return your analysis as a JSON array of vulnerability objects with the following structure:
```json
[
  {{
    "vulnerability_type": "sql_injection",
    "severity": "high",
    "line_number": 42,
    "description": "SQL injection vulnerability due to string concatenation",
    "code_snippet": "query = 'SELECT * FROM users WHERE id = ' + user_id",
    "recommendation": "Use parameterized queries or prepared statements",
    "cwe_id": "CWE-89",
    "confidence": 0.9
  }}
]
```

If no vulnerabilities are found, return an empty array: []"""

        return prompt
    
    def _create_zero_day_prompt(self, file_path: str, code_content: str, repo_info: Dict[str, Any]) -> str:
        """Create zero-day detection prompt for DeepHat"""
        prompt = f"""You are DeepHat, an advanced cybersecurity AI specializing in zero-day vulnerability detection.

Analyze the following Python code for potential zero-day vulnerabilities - novel security issues that may not be covered by traditional security scanners:

File: {file_path}

Code:
```python
{code_content}
```

Look for:
1. Novel attack vectors or unusual code patterns
2. Complex logic flaws that could lead to security bypasses
3. Subtle race conditions or timing attacks
4. Unconventional use of libraries that might introduce vulnerabilities
5. Business logic flaws that could be exploited
6. Novel injection techniques
7. Unusual cryptographic implementations
8. Complex state management issues

For each potential zero-day pattern found, provide:
- Description of the potential vulnerability
- Why it might be a zero-day (novel or uncommon pattern)
- Potential impact
- Zero-day likelihood score (0.0 to 1.0)
- Exploitation complexity (low, medium, high)

Return as JSON array:
```json
[
  {{
    "vulnerability_type": "zero_day_pattern",
    "severity": "high",
    "description": "Novel authentication bypass through state manipulation",
    "zero_day_likelihood": 0.8,
    "exploitation_complexity": "medium",
    "potential_impact": "Complete authentication bypass",
    "confidence": 0.7
  }}
]
```

If no zero-day patterns are detected, return: []"""

        return prompt
    
    @track_function(metadata={"agent_type": "deephat_security", "operation": "generate_response"})
    async def _generate_deephat_response(self, prompt: str) -> str:
        """Generate response from DeepHat model"""
        try:
            # Prepare messages for chat template
            messages = [
                {"role": "system", "content": "You are DeepHat, created by Kindo.ai. You are a helpful assistant that is an expert in Cybersecurity and DevOps."},
                {"role": "user", "content": prompt}
            ]
            
            # Apply chat template
            text = self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True
            )
            
            # Tokenize input
            model_inputs = self.tokenizer([text], return_tensors="pt").to(self.model.device)
            
            # Generate response
            generated_ids = self.model.generate(
                **model_inputs,
                max_new_tokens=self.deephat_config.max_new_tokens,
                temperature=self.deephat_config.temperature,
                do_sample=True if self.deephat_config.temperature > 0 else False,
                pad_token_id=self.tokenizer.eos_token_id
            )
            
            # Decode response
            generated_ids = [
                output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
            ]
            
            response = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
            return response
            
        except Exception as e:
            self.logger.error(f"Error generating DeepHat response: {str(e)}")
            raise
    
    def _parse_vulnerability_response(self, response: str, file_path: str, code_content: str) -> List[VulnerabilityFinding]:
        """Parse DeepHat response to extract vulnerability findings"""
        findings = []
        
        try:
            # Try to extract JSON from response
            json_start = response.find('[')
            json_end = response.rfind(']') + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = response[json_start:json_end]
                vulnerabilities = json.loads(json_str)
                
                for vuln in vulnerabilities:
                    finding = VulnerabilityFinding(
                        file_path=file_path,
                        line_number=vuln.get("line_number"),
                        vulnerability_type=vuln.get("vulnerability_type", "unknown"),
                        severity=vuln.get("severity", "medium"),
                        confidence=float(vuln.get("confidence", 0.5)),
                        description=vuln.get("description", ""),
                        code_snippet=vuln.get("code_snippet"),
                        recommendation=vuln.get("recommendation"),
                        cwe_id=vuln.get("cwe_id"),
                        detection_method="llm_analysis"
                    )
                    
                    # Assess confidence using base method
                    assessed_confidence = self.assess_vulnerability_confidence(vuln)
                    finding.confidence = max(finding.confidence, assessed_confidence)
                    
                    findings.append(finding)
                    
        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse JSON response: {str(e)}")
            # Fallback: try to extract vulnerabilities from text
            findings.extend(self._parse_text_response(response, file_path))
        except Exception as e:
            self.logger.error(f"Error parsing vulnerability response: {str(e)}")
        
        return findings
    
    def _parse_zero_day_response(self, response: str, file_path: str, code_content: str) -> List[VulnerabilityFinding]:
        """Parse zero-day detection response"""
        findings = []
        
        try:
            json_start = response.find('[')
            json_end = response.rfind(']') + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = response[json_start:json_end]
                zero_day_patterns = json.loads(json_str)
                
                for pattern in zero_day_patterns:
                    finding = VulnerabilityFinding(
                        file_path=file_path,
                        vulnerability_type=pattern.get("vulnerability_type", "zero_day_pattern"),
                        severity=pattern.get("severity", "medium"),
                        confidence=float(pattern.get("confidence", 0.5)),
                        description=pattern.get("description", ""),
                        detection_method="zero_day_analysis",
                        zero_day_likelihood=float(pattern.get("zero_day_likelihood", 0.0))
                    )
                    findings.append(finding)
                    
        except Exception as e:
            self.logger.error(f"Error parsing zero-day response: {str(e)}")
        
        return findings
    
    def _parse_text_response(self, response: str, file_path: str) -> List[VulnerabilityFinding]:
        """Fallback text parsing for non-JSON responses"""
        findings = []
        
        # Simple text parsing as fallback
        if "vulnerability" in response.lower() or "injection" in response.lower():
            finding = VulnerabilityFinding(
                file_path=file_path,
                vulnerability_type="potential_vulnerability",
                severity="medium",
                confidence=0.3,
                description=f"Potential vulnerability detected in text analysis: {response[:200]}...",
                detection_method="text_analysis"
            )
            findings.append(finding)
        
        return findings
    
    def _generate_analysis_summary(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Generate summary of vulnerability analysis"""
        if not findings:
            return {"total_vulnerabilities": 0, "risk_level": "low"}
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        vuln_type_counts = {}
        total_zero_day_likelihood = 0
        
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            vuln_type_counts[finding.vulnerability_type] = vuln_type_counts.get(finding.vulnerability_type, 0) + 1
            total_zero_day_likelihood += finding.zero_day_likelihood
        
        # Determine overall risk level
        if severity_counts["critical"] > 0:
            risk_level = "critical"
        elif severity_counts["high"] > 0:
            risk_level = "high"
        elif severity_counts["medium"] > 0:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "total_vulnerabilities": len(findings),
            "severity_breakdown": severity_counts,
            "vulnerability_types": vuln_type_counts,
            "risk_level": risk_level,
            "average_confidence": sum(f.confidence for f in findings) / len(findings),
            "zero_day_potential": total_zero_day_likelihood / len(findings) if findings else 0.0
        }
