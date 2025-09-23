"""
DeepHat Interface - Utilities for interacting with DeepHat-V1-7B model
"""

import os
from typing import Dict, List, Optional, Any
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch


class DeepHatInterface:
    """Interface for DeepHat-V1-7B model operations"""
    
    def __init__(
        self,
        model_name: str = "DeepHat/DeepHat-V1-7B",
        model_path: Optional[str] = None,
        device: str = "auto",
        torch_dtype: str = "auto"
    ):
        self.model_name = model_name
        self.model_path = model_path
        self.device = device
        self.torch_dtype = torch_dtype
        self.model = None
        self.tokenizer = None
        self.is_loaded = False
    
    def load_model(self) -> bool:
        """
        Load the DeepHat model and tokenizer
        
        Returns:
            True if successful, False otherwise
        """
        try:
            model_name_or_path = self.model_path or self.model_name
            
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(model_name_or_path)
            
            # Determine torch dtype
            torch_dtype = self._get_torch_dtype()
            
            # Load model
            self.model = AutoModelForCausalLM.from_pretrained(
                model_name_or_path,
                torch_dtype=torch_dtype,
                device_map=self.device,
                trust_remote_code=True
            )
            
            self.is_loaded = True
            return True
            
        except Exception as e:
            print(f"Failed to load DeepHat model: {str(e)}")
            return False
    
    def _get_torch_dtype(self):
        """Get appropriate torch dtype"""
        if self.torch_dtype == "float16":
            return torch.float16
        elif self.torch_dtype == "bfloat16":
            return torch.bfloat16
        else:
            return "auto"
    
    def generate_response(
        self,
        prompt: str,
        max_new_tokens: int = 2048,
        temperature: float = 0.1,
        do_sample: bool = False
    ) -> str:
        """
        Generate response from DeepHat model
        
        Args:
            prompt: Input prompt
            max_new_tokens: Maximum new tokens to generate
            temperature: Temperature for generation
            do_sample: Whether to use sampling
            
        Returns:
            Generated response
        """
        if not self.is_loaded:
            raise RuntimeError("Model not loaded. Call load_model() first.")
        
        # Prepare messages for chat template
        messages = [
            {"role": "system", "content": "You are DeepHat. You are a helpful assistant that is an expert in Cybersecurity and DevOps."},
            {"role": "user", "content": prompt}
        ]
        
        # Apply chat template
        text = self.tokenizer.apply_chat_template( # type: ignore
            messages,
            tokenize=False,
            add_generation_prompt=True
        )
        
        # Tokenize input
        model_inputs = self.tokenizer([text], return_tensors="pt").to(self.model.device) # type: ignore
        
        # Determine sampling
        if do_sample is None:
            do_sample = temperature > 0
        
        # Generate response
        generated_ids = self.model.generate( # type: ignore
            **model_inputs,
            max_new_tokens=max_new_tokens,
            temperature=temperature,
            do_sample=do_sample,
            pad_token_id=self.tokenizer.eos_token_id # type: ignore
        )
        
        # Decode response
        generated_ids = [
            output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
        ]
        
        response = self.tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0] # type: ignore
        return response
    
    def analyze_code_for_vulnerabilities(
        self,
        code: str,
        file_path: str = "unknown",
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Analyze code for vulnerabilities using DeepHat
        
        Args:
            code: Code to analyze
            file_path: Path of the file being analyzed
            context: Additional context (dependencies, etc.)
            
        Returns:
            Analysis response from DeepHat
        """
        context_str = ""
        if context and context.get("dependencies"):
            deps = context["dependencies"][:10]  # Limit to first 10
            context_str = f"\n\nRepository dependencies: {', '.join(deps)}"
        
        prompt = f"""You are DeepHat, a cybersecurity expert analyzing Python code for vulnerabilities.

Analyze the following Python file for security vulnerabilities:

File: {file_path}
{context_str}

Code:
```python
{code}
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
        
        return self.generate_response(prompt)
    
    def detect_zero_day_patterns(
        self,
        code: str,
        file_path: str = "unknown"
    ) -> str:
        """
        Detect potential zero-day vulnerability patterns
        
        Args:
            code: Code to analyze
            file_path: Path of the file being analyzed
            
        Returns:
            Zero-day analysis response from DeepHat
        """
        prompt = f"""You are DeepHat, an advanced cybersecurity AI specializing in zero-day vulnerability detection.

Analyze the following Python code for potential zero-day vulnerabilities - novel security issues that may not be covered by traditional security scanners:

File: {file_path}

Code:
```python
{code}
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
        
        return self.generate_response(prompt)
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the loaded model
        
        Returns:
            Dict containing model information
        """
        return {
            "model_name": self.model_name,
            "model_path": self.model_path,
            "device": self.device,
            "torch_dtype": self.torch_dtype,
            "is_loaded": self.is_loaded,
            "tokenizer_vocab_size": len(self.tokenizer) if self.tokenizer else 0,
            "model_parameters": sum(p.numel() for p in self.model.parameters()) if self.model else 0
        }
    
    def unload_model(self) -> None:
        """Unload the model to free memory"""
        if self.model:
            del self.model
            self.model = None
        
        if self.tokenizer:
            del self.tokenizer
            self.tokenizer = None
        
        self.is_loaded = False
        
        # Clear GPU cache if using CUDA
        if torch.cuda.is_available():
            torch.cuda.empty_cache()


# Convenience functions
def create_deephat_interface(
    model_name: str = "DeepHat/DeepHat-V1-7B",
    model_path: Optional[str] = None,
    device: str = "auto",
    torch_dtype: str = "auto"
) -> DeepHatInterface:
    """
    Create and load a DeepHat interface
    
    Args:
        model_name: Name of the DeepHat model
        model_path: Optional local path to model
        device: Device to load model on
        torch_dtype: Torch data type
        
    Returns:
        Loaded DeepHatInterface instance
    """
    interface = DeepHatInterface(model_name, model_path, device, torch_dtype)
    
    if not interface.load_model():
        raise RuntimeError("Failed to load DeepHat model")
    
    return interface


def analyze_code_simple(code: str, file_path: str = "unknown") -> str:
    """
    Simple function to analyze code with DeepHat
    
    Args:
        code: Code to analyze
        file_path: Path of the file
        
    Returns:
        Analysis result
    """
    interface = create_deephat_interface()
    try:
        return interface.analyze_code_for_vulnerabilities(code, file_path)
    finally:
        interface.unload_model()
