"""
DeepHat Interface - Utilities for interacting with DeepHat-V1-7B model
Supports both local and remote Hugging Face deployment
"""

import os
import requests
import time
from typing import Dict, List, Optional, Any
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
from tqdm import tqdm

# Try to load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv not installed, skip
    pass

# Try to import huggingface_hub for alternative API access
try:
    from huggingface_hub import InferenceClient
    HF_HUB_AVAILABLE = True
except ImportError:
    InferenceClient = None
    HF_HUB_AVAILABLE = False


class DeepHatInterface:
    """Interface for DeepHat-V1-7B model operations"""
    
    def __init__(
        self,
        model_name: str = "DeepHat/DeepHat-V1-7B",
        model_path: Optional[str] = None,
        device: str = "auto",
        torch_dtype: str = "auto",
        use_remote: bool = False,
        hf_api_token: Optional[str] = None,
        remote_endpoint: Optional[str] = None
    ):
        self.model_name = model_name
        self.model_path = model_path
        self.device = device
        self.torch_dtype = torch_dtype
        self.use_remote = use_remote
        
        # Check multiple possible environment variable names for HF token
        self.hf_api_token = (
            hf_api_token or 
            os.getenv("HUGGINGFACE_API_TOKEN") or 
            os.getenv("HF_TOKEN") or
            os.getenv("HUGGINGFACE_TOKEN")
        )
        
        self.remote_endpoint = remote_endpoint
        
        # Local model attributes
        self.model = None
        self.tokenizer = None
        self.is_loaded = False
        
        # Remote model attributes
        self.remote_ready = False
        self.hf_client = None  # For Hugging Face Hub client
    
    def load_model(self) -> bool:
        """
        Load the DeepHat model and tokenizer (local) or setup remote connection
        
        Returns:
            True if successful, False otherwise
        """
        if self.use_remote:
            return self._setup_remote_connection()
        else:
            return self._load_local_model()
    
    def _setup_remote_connection(self) -> bool:
        """Setup connection to remote Hugging Face deployment"""
        try:
            print("🌐 Setting up remote DeepHat connection...")
            
            if not self.hf_api_token:
                print("❌ Error: HUGGINGFACE_API_TOKEN is required for remote deployment")
                print("💡 Tip: Set environment variable HUGGINGFACE_API_TOKEN or HF_TOKEN")
                return False
            
            # Try Hugging Face Hub with Featherless AI first (recommended approach)
            if HF_HUB_AVAILABLE:
                print("🔌 Trying Hugging Face Hub with Featherless AI provider...")
                if self._setup_hf_hub_connection():
                    return True
            
            # Fallback to direct Inference API
            print("🔌 Trying direct Hugging Face Inference API...")
            return self._setup_inference_api_connection()
            
        except Exception as e:
            print(f"❌ Error setting up remote connection: {e}")
            return False
    
    def _setup_hf_hub_connection(self) -> bool:
        """Setup connection using Hugging Face Hub with Featherless AI provider"""
        try:
            if not HF_HUB_AVAILABLE or InferenceClient is None:
                print("❌ huggingface_hub not available")
                return False
            
            client = InferenceClient(
                provider="featherless-ai",
                api_key=self.hf_api_token
            )
            
            # Test the connection with a simple message
            print(f"🧪 Testing connection to {self.model_name}...")
            completion = client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {
                        "role": "user",
                        "content": "Hello, this is a test message."
                    }
                ],
                max_tokens=10
            )
            
            if completion and completion.choices:
                self.hf_client = client
                self.remote_ready = True
                print(f"✅ Hugging Face Hub connection established with {self.model_name}")
                return True
            else:
                print(f"❌ No response from {self.model_name} via HF Hub")
                return False
                
        except Exception as e:
            print(f"❌ HF Hub connection failed: {e}")
            return False
    
    def _setup_inference_api_connection(self) -> bool:
        """Setup connection using direct Inference API (fallback method)"""
        try:
            # Check if the specific DeepHat model is available
            # If not, we can fallback to a compatible model
            fallback_models = [
                self.model_name,  # Original DeepHat model
                "microsoft/DialoGPT-medium",  # Fallback for testing
                "gpt2",  # Well-known model that should be available
                "distilbert-base-uncased"  # Another well-known model
            ]
            
            # Determine endpoint
            endpoint_base = "https://api-inference.huggingface.co/models/"
            
            for model_name in fallback_models:
                try:
                    if self.remote_endpoint:
                        endpoint = self.remote_endpoint
                    else:
                        endpoint = endpoint_base + model_name
                    
                    print(f"🔌 Testing connection to model: {model_name}")
                    
                    # Test connection
                    headers = {
                        "Authorization": f"Bearer {self.hf_api_token}",
                        "Content-Type": "application/json"
                    }
                    
                    test_payload = {
                        "inputs": "Hello, this is a test.",
                        "parameters": {
                            "max_new_tokens": 10,
                            "temperature": 0.1,
                            "return_full_text": False
                        },
                        "options": {
                            "wait_for_model": True
                        }
                    }
                    
                    response = requests.post(endpoint, headers=headers, json=test_payload, timeout=30)
                    
                    if response.status_code == 200:
                        self.remote_endpoint = endpoint
                        self.model_name = model_name  # Update to working model
                        self.remote_ready = True
                        print(f"✅ Remote connection established successfully with {model_name}")
                        if model_name != fallback_models[0]:
                            print(f"⚠️  Note: Using fallback model {model_name} instead of {fallback_models[0]}")
                        return True
                    elif response.status_code == 401:
                        print(f"❌ Authentication failed. Your Hugging Face token is invalid or expired.")
                        print(f"💡 Please update your HUGGINGFACE_API_TOKEN in .env file")
                        print(f"💡 Get a new token at: https://huggingface.co/settings/tokens")
                        return False
                    elif response.status_code == 503:
                        print(f"⏳ Model {model_name} is loading, trying next...")
                        continue
                    elif response.status_code == 404:
                        print(f"❌ Model {model_name} not found or not available via Inference API, trying next...")
                        continue
                    else:
                        print(f"⚠️  Model {model_name} returned {response.status_code}: {response.text}")
                        continue
                        
                except Exception as e:
                    print(f"❌ Error testing {model_name}: {str(e)}")
                    continue
            
            print("❌ No compatible models found on Hugging Face Inference API")
            print("💡 Suggestions:")
            print("   - Verify your HUGGINGFACE_API_TOKEN is valid")
            print("   - Try using local deployment instead (remove --remote flag)")
            print("   - Check if the model exists and supports Inference API")
            return False
                
        except Exception as e:
            print(f"❌ Failed to setup remote DeepHat connection: {str(e)}")
            return False
    
    def _load_local_model(self) -> bool:
        """Load local DeepHat model with progress tracking"""
        try:
            model_name_or_path = self.model_path or self.model_name
            print(f"🔧 Loading local DeepHat model: {model_name_or_path}")
            
            # Load tokenizer with progress
            print("📝 Loading tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained(model_name_or_path)
            print("✅ Tokenizer loaded successfully")
            
            # Determine torch dtype
            torch_dtype = self._get_torch_dtype()
            
            # Load model with progress
            print("🧠 Loading model weights... (this may take several minutes)")
            print("💾 Expected download size: ~15GB for DeepHat-V1-7B")
            
            self.model = AutoModelForCausalLM.from_pretrained(
                model_name_or_path,
                torch_dtype=torch_dtype,
                device_map=self.device,
                trust_remote_code=True
            )
            
            self.is_loaded = True
            print("✅ Local DeepHat model loaded successfully")
            return True
            
        except Exception as e:
            print(f"❌ Failed to load local DeepHat model: {str(e)}")
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
        do_sample: Optional[bool] = None,
        show_progress: bool = False
    ) -> str:
        """
        Generate response from DeepHat model (local or remote)
        
        Args:
            prompt: Input prompt
            max_new_tokens: Maximum new tokens to generate
            temperature: Temperature for generation
            do_sample: Whether to use sampling
            show_progress: Whether to show progress bar
            
        Returns:
            Generated response
        """
        if self.use_remote:
            return self._generate_remote_response(prompt, max_new_tokens, temperature, show_progress)
        else:
            return self._generate_local_response(prompt, max_new_tokens, temperature, do_sample, show_progress)
    
    def _generate_remote_response(
        self, 
        prompt: str, 
        max_new_tokens: int, 
        temperature: float,
        show_progress: bool = False
    ) -> str:
        """Generate response using remote Hugging Face API"""
        if not self.remote_ready:
            raise RuntimeError("Remote connection not established. Call load_model() first.")
        
        try:
            # Try HF Hub client first if available
            if self.hf_client is not None:
                return self._generate_hf_hub_response(prompt, max_new_tokens, temperature, show_progress)
            else:
                return self._generate_inference_api_response(prompt, max_new_tokens, temperature, show_progress)
                
        except Exception as e:
            raise RuntimeError(f"Remote generation failed: {str(e)}")
    
    def _generate_hf_hub_response(
        self, 
        prompt: str, 
        max_new_tokens: int, 
        temperature: float,
        show_progress: bool = False
    ) -> str:
        """Generate response using Hugging Face Hub client"""
        try:
            if self.hf_client is None:
                raise RuntimeError("HF Hub client not initialized")
                
            if show_progress:
                print("🌐 Sending request to remote DeepHat via HF Hub...")
            
            messages = [
                {"role": "system", "content": "You are DeepHat, created by Kindo.ai. You are a helpful assistant that is an expert in Cybersecurity and DevOps."},
                {"role": "user", "content": prompt}
            ]
            
            completion = self.hf_client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                max_tokens=max_new_tokens,
                temperature=temperature
            )
            
            if completion and completion.choices and len(completion.choices) > 0:
                response_content = completion.choices[0].message.content
                if show_progress:
                    print("✅ Remote response received via HF Hub")
                return response_content or ""
            else:
                raise ValueError("No response received from HF Hub")
                
        except Exception as e:
            raise RuntimeError(f"HF Hub generation failed: {str(e)}")
    
    def _generate_inference_api_response(
        self, 
        prompt: str, 
        max_new_tokens: int, 
        temperature: float,
        show_progress: bool = False
    ) -> str:
        """Generate response using direct Inference API"""
        try:
            headers = {
                "Authorization": f"Bearer {self.hf_api_token}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "inputs": prompt,
                "parameters": {
                    "max_new_tokens": max_new_tokens,
                    "temperature": temperature,
                    "do_sample": temperature > 0,
                    "return_full_text": False
                }
            }
            
            if show_progress:
                print("🌐 Sending request to remote DeepHat via Inference API...")
            
            response = requests.post(
                self.remote_endpoint or "", 
                headers=headers, 
                json=payload, 
                timeout=300  # 5 minute timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                if isinstance(result, list) and len(result) > 0:
                    generated_text = result[0].get("generated_text", "")
                    if show_progress:
                        print("✅ Remote response received via Inference API")
                    return generated_text
                else:
                    raise ValueError("Unexpected response format")
            else:
                raise ValueError(f"Remote API error: {response.status_code} - {response.text}")
                
        except Exception as e:
            raise RuntimeError(f"Inference API generation failed: {str(e)}")
    
    def _generate_local_response(
        self, 
        prompt: str, 
        max_new_tokens: int, 
        temperature: float, 
        do_sample: Optional[bool] = None,
        show_progress: bool = False
    ) -> str:
        """Generate response using local model"""
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
        
        if show_progress:
            print(f"🧠 Generating response locally (max_tokens: {max_new_tokens})...")
        
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
        
        if show_progress:
            print("✅ Local response generated")
        
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
    torch_dtype: str = "auto",
    use_remote: bool = False,
    hf_api_token: Optional[str] = None,
    remote_endpoint: Optional[str] = None
) -> DeepHatInterface:
    """
    Create and load a DeepHat interface
    
    Args:
        model_name: Name of the DeepHat model
        model_path: Optional local path to model
        device: Device to load model on
        torch_dtype: Torch data type
        use_remote: Whether to use remote Hugging Face deployment
        hf_api_token: Hugging Face API token for remote access
        remote_endpoint: Custom remote endpoint URL
        
    Returns:
        Loaded DeepHatInterface instance
    """
    interface = DeepHatInterface(
        model_name, model_path, device, torch_dtype,
        use_remote, hf_api_token, remote_endpoint
    )
    
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
