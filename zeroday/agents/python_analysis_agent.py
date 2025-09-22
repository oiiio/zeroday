"""
Python Analysis Agent - Performs static analysis and code parsing for Python files
"""

import ast
import os
import re
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from .base_agent import SecurityBaseAgent, SecurityAgentConfig
from nat.profiler.decorators.function_tracking import track_function


class PythonAnalysisConfig(SecurityAgentConfig):
    """Configuration for Python Analysis Agent"""
    enable_ast_analysis: bool = Field(default=True, description="Enable AST-based analysis")
    enable_pattern_matching: bool = Field(default=True, description="Enable pattern-based vulnerability detection")
    enable_import_analysis: bool = Field(default=True, description="Enable import and dependency analysis")
    dangerous_functions: List[str] = Field(
        default=[
            "eval", "exec", "compile", "open", "input", "raw_input",
            "subprocess.call", "subprocess.run", "subprocess.Popen",
            "os.system", "os.popen", "os.execv", "os.execve",
            "pickle.loads", "pickle.load", "yaml.load", "yaml.unsafe_load"
        ],
        description="List of potentially dangerous functions to flag"
    )
    suspicious_patterns: List[str] = Field(
        default=[
            r"password\s*=\s*['\"][^'\"]+['\"]",  # Hardcoded passwords
            r"api_key\s*=\s*['\"][^'\"]+['\"]",   # Hardcoded API keys
            r"secret\s*=\s*['\"][^'\"]+['\"]",    # Hardcoded secrets
            r"SELECT\s+.*\s+FROM\s+.*\s*\+",      # SQL injection patterns
            r"\.format\s*\([^)]*\)",              # String formatting that might be vulnerable
            r"f['\"].*\{.*\}.*['\"]",             # F-string patterns
        ],
        description="Regex patterns for suspicious code"
    )


class CodeAnalysisResult(BaseModel):
    """Result of Python code analysis"""
    file_path: str
    ast_analysis: Dict[str, Any]
    dangerous_calls: List[Dict[str, Any]]
    suspicious_patterns: List[Dict[str, Any]]
    imports: List[str]
    functions: List[str]
    classes: List[str]
    complexity_score: float
    security_score: float


class PythonAnalysisAgent(SecurityBaseAgent):
    """
    Agent for static analysis of Python code
    
    Capabilities:
    - AST-based code analysis
    - Pattern-based vulnerability detection
    - Import and dependency analysis
    - Code complexity assessment
    - Security scoring
    """
    
    def __init__(self, config: PythonAnalysisConfig):
        super().__init__(config)
        self.analysis_config = config
        
    async def _initialize_agent_specific(self) -> None:
        """Initialize Python analysis specific components"""
        self.logger.info("Python Analysis Agent initialized")
    
    @track_function(metadata={"agent_type": "python_analysis", "operation": "execute_core"})
    async def _execute_core(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Core execution logic for Python analysis
        
        Args:
            input_data: Must contain 'python_files'
            
        Returns:
            Dict containing analysis results
        """
        if not self.validate_input(input_data):
            raise ValueError("Invalid input data")
        
        python_files = input_data["python_files"]
        self.logger.info(f"Starting Python analysis of {len(python_files)} files")
        
        # Filter files that can be analyzed
        analyzable_files = self.filter_analyzable_files(python_files)
        self.logger.info(f"Analyzing {len(analyzable_files)} files within size limits")
        
        # Analyze each file
        analysis_results = []
        for file_path in analyzable_files:
            try:
                result = await self._analyze_python_file(file_path)
                analysis_results.append(result)
            except Exception as e:
                self.logger.error(f"Failed to analyze {file_path}: {str(e)}")
        
        # Generate summary
        summary = self._generate_analysis_summary(analysis_results)
        
        return {
            "status": "success",
            "analyzed_files": len(analysis_results),
            "analysis_results": [r.dict() for r in analysis_results],
            "summary": summary
        }
    
    def validate_input(self, input_data: Dict[str, Any]) -> bool:
        """Validate input contains required data"""
        if not isinstance(input_data, dict):
            return False
        
        python_files = input_data.get("python_files")
        if not python_files or not isinstance(python_files, list):
            return False
            
        return True
    
    @track_function(metadata={"agent_type": "python_analysis", "operation": "analyze_file"})
    async def _analyze_python_file(self, file_path: str) -> CodeAnalysisResult:
        """Analyze a single Python file"""
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()
            
            # Initialize result
            result = CodeAnalysisResult(
                file_path=file_path,
                ast_analysis={},
                dangerous_calls=[],
                suspicious_patterns=[],
                imports=[],
                functions=[],
                classes=[],
                complexity_score=0.0,
                security_score=0.0
            )
            
            # Perform AST analysis
            if self.analysis_config.enable_ast_analysis:
                result.ast_analysis = await self._perform_ast_analysis(code_content)
                result.imports = result.ast_analysis.get("imports", [])
                result.functions = result.ast_analysis.get("functions", [])
                result.classes = result.ast_analysis.get("classes", [])
                result.dangerous_calls = result.ast_analysis.get("dangerous_calls", [])
            
            # Perform pattern matching
            if self.analysis_config.enable_pattern_matching:
                result.suspicious_patterns = await self._find_suspicious_patterns(code_content)
            
            # Calculate complexity and security scores
            result.complexity_score = self._calculate_complexity_score(result.ast_analysis)
            result.security_score = self._calculate_security_score(result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing {file_path}: {str(e)}")
            # Return minimal result on error
            return CodeAnalysisResult(
                file_path=file_path,
                ast_analysis={"error": str(e)},
                dangerous_calls=[],
                suspicious_patterns=[],
                imports=[],
                functions=[],
                classes=[],
                complexity_score=0.0,
                security_score=0.0
            )
    
    @track_function(metadata={"agent_type": "python_analysis", "operation": "ast_analysis"})
    async def _perform_ast_analysis(self, code_content: str) -> Dict[str, Any]:
        """Perform AST-based analysis of Python code"""
        try:
            tree = ast.parse(code_content)
            
            analysis = {
                "imports": [],
                "functions": [],
                "classes": [],
                "dangerous_calls": [],
                "variables": [],
                "decorators": [],
                "ast_nodes": 0
            }
            
            # Walk through AST nodes
            for node in ast.walk(tree):
                analysis["ast_nodes"] += 1
                
                # Extract imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        analysis["imports"].append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for alias in node.names:
                        analysis["imports"].append(f"{module}.{alias.name}")
                
                # Extract function definitions
                elif isinstance(node, ast.FunctionDef):
                    analysis["functions"].append({
                        "name": node.name,
                        "line": node.lineno,
                        "args": len(node.args.args),
                        "decorators": [d.id if isinstance(d, ast.Name) else str(d) for d in node.decorator_list]
                    })
                
                # Extract class definitions
                elif isinstance(node, ast.ClassDef):
                    analysis["classes"].append({
                        "name": node.name,
                        "line": node.lineno,
                        "bases": [b.id if isinstance(b, ast.Name) else str(b) for b in node.bases]
                    })
                
                # Check for dangerous function calls
                elif isinstance(node, ast.Call):
                    func_name = self._get_function_name(node.func)
                    if func_name in self.analysis_config.dangerous_functions:
                        analysis["dangerous_calls"].append({
                            "function": func_name,
                            "line": node.lineno,
                            "args": len(node.args)
                        })
                
                # Extract variable assignments
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            analysis["variables"].append({
                                "name": target.id,
                                "line": node.lineno
                            })
            
            return analysis
            
        except SyntaxError as e:
            return {"error": f"Syntax error: {str(e)}"}
        except Exception as e:
            return {"error": f"AST analysis error: {str(e)}"}
    
    def _get_function_name(self, func_node) -> str:
        """Extract function name from AST node"""
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            value_name = self._get_function_name(func_node.value)
            return f"{value_name}.{func_node.attr}"
        else:
            return str(func_node)
    
    @track_function(metadata={"agent_type": "python_analysis", "operation": "pattern_matching"})
    async def _find_suspicious_patterns(self, code_content: str) -> List[Dict[str, Any]]:
        """Find suspicious patterns in code using regex"""
        suspicious_findings = []
        
        lines = code_content.split('\n')
        
        for pattern in self.analysis_config.suspicious_patterns:
            try:
                compiled_pattern = re.compile(pattern, re.IGNORECASE)
                
                for line_num, line in enumerate(lines, 1):
                    matches = compiled_pattern.finditer(line)
                    for match in matches:
                        suspicious_findings.append({
                            "pattern": pattern,
                            "line": line_num,
                            "match": match.group(),
                            "start": match.start(),
                            "end": match.end()
                        })
                        
            except re.error as e:
                self.logger.warning(f"Invalid regex pattern {pattern}: {str(e)}")
        
        return suspicious_findings
    
    def _calculate_complexity_score(self, ast_analysis: Dict[str, Any]) -> float:
        """Calculate code complexity score"""
        if "error" in ast_analysis:
            return 0.0
        
        # Simple complexity calculation based on AST nodes and structure
        base_score = min(ast_analysis.get("ast_nodes", 0) / 100.0, 10.0)
        
        # Add complexity for functions and classes
        function_complexity = len(ast_analysis.get("functions", [])) * 0.5
        class_complexity = len(ast_analysis.get("classes", [])) * 0.3
        
        # Add complexity for dangerous calls
        danger_complexity = len(ast_analysis.get("dangerous_calls", [])) * 1.0
        
        total_complexity = base_score + function_complexity + class_complexity + danger_complexity
        return min(total_complexity, 10.0)  # Cap at 10.0
    
    def _calculate_security_score(self, result: CodeAnalysisResult) -> float:
        """Calculate security score (lower is better)"""
        security_issues = 0
        
        # Count dangerous function calls
        security_issues += len(result.dangerous_calls) * 2
        
        # Count suspicious patterns
        security_issues += len(result.suspicious_patterns)
        
        # Check for risky imports
        risky_imports = ["pickle", "subprocess", "os", "eval", "exec"]
        for imp in result.imports:
            if any(risky in imp.lower() for risky in risky_imports):
                security_issues += 1
        
        # Convert to score (0-10, where 0 is most secure)
        return min(security_issues, 10.0)
    
    def _generate_analysis_summary(self, results: List[CodeAnalysisResult]) -> Dict[str, Any]:
        """Generate summary of analysis results"""
        if not results:
            return {"total_files": 0}
        
        total_dangerous_calls = sum(len(r.dangerous_calls) for r in results)
        total_suspicious_patterns = sum(len(r.suspicious_patterns) for r in results)
        avg_complexity = sum(r.complexity_score for r in results) / len(results)
        avg_security_score = sum(r.security_score for r in results) / len(results)
        
        # Collect all imports
        all_imports = set()
        for result in results:
            all_imports.update(result.imports)
        
        # Collect all functions
        all_functions = []
        for result in results:
            all_functions.extend(result.functions)
        
        return {
            "total_files": len(results),
            "total_dangerous_calls": total_dangerous_calls,
            "total_suspicious_patterns": total_suspicious_patterns,
            "average_complexity_score": round(avg_complexity, 2),
            "average_security_score": round(avg_security_score, 2),
            "unique_imports": len(all_imports),
            "total_functions": len(all_functions),
            "risk_level": self._assess_risk_level(avg_security_score, total_dangerous_calls, total_suspicious_patterns)
        }
    
    def _assess_risk_level(self, avg_security_score: float, dangerous_calls: int, suspicious_patterns: int) -> str:
        """Assess overall risk level"""
        if avg_security_score >= 7 or dangerous_calls >= 10 or suspicious_patterns >= 20:
            return "high"
        elif avg_security_score >= 4 or dangerous_calls >= 5 or suspicious_patterns >= 10:
            return "medium"
        else:
            return "low"
