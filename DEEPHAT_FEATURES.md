# DeepHat Enhanced Features

This document describes the enhanced features added to the DeepHat Security Agent for improved usability and flexibility.

## 🌐 Remote Deployment Support

The DeepHat Security Agent now supports both local and remote model deployment:

### Local Deployment (Default)
- Downloads and runs the DeepHat-V1-7B model locally
- Requires ~15GB disk space and significant VRAM/RAM
- Full control and privacy
- No API limits

### Remote Deployment via Hugging Face
- Uses Hugging Face Inference API
- No local model download required
- Faster startup time
- Requires API token and internet connection

#### Usage Examples:

**Local Mode:**
```bash
# Uses local model (default)
python scripts/run_analysis.py https://github.com/user/repo

# Environment variable
export USE_DEEPHAT_REMOTE=false
python scripts/run_analysis.py https://github.com/user/repo
```

**Remote Mode:**
```bash
# Command line flag
python scripts/run_analysis.py --remote https://github.com/user/repo

# Environment variables
export USE_DEEPHAT_REMOTE=true
export HUGGINGFACE_API_TOKEN=your_token_here
python scripts/run_analysis.py https://github.com/user/repo
```

#### Setup for Remote Mode:

1. **Get Hugging Face API Token:**
   - Go to https://huggingface.co/settings/tokens
   - Create a new token with read access
   - Set environment variable: `export HUGGINGFACE_API_TOKEN=your_token_here`

2. **Configuration:**
   ```python
   # In your code
   deephat_config = DeepHatConfig(
       use_remote=True,
       hf_api_token="your_token_here"  # or use env var
   )
   ```

## 📊 Progress Tracking

Enhanced progress tracking shows real-time analysis progress:

### Features:
- **File-by-file progress**: Shows which file is currently being analyzed
- **Progress percentage**: Displays completion percentage
- **Vulnerability counts**: Shows findings per file
- **Real-time feedback**: Immediate feedback on analysis progress

### Example Output:
```
🔍 DeepHat Analysis Progress:
📁 Files to analyze: 5
🔄 [1/5] (20.0%) Analyzing: ./app.py
   ⚠️  Found 3 potential vulnerabilities
🔄 [2/5] (40.0%) Analyzing: ./models.py
🔄 [3/5] (60.0%) Analyzing: ./views.py
   ⚠️  Found 1 potential vulnerabilities
🔄 [4/5] (80.0%) Analyzing: ./utils.py
🔄 [5/5] (100.0%) Analyzing: ./config.py
✅ Analysis complete! Found 4 total potential vulnerabilities
```

### Configuration:
```python
# Enable/disable progress tracking
deephat_config = DeepHatConfig(
    show_progress=True  # Set to False to disable
)
```

## 🔧 API Reference

### DeepHatInterface

Enhanced interface supporting both local and remote deployments:

```python
from zeroday.tools.deephat_interface import DeepHatInterface

# Local deployment
interface_local = DeepHatInterface(
    model_name="DeepHat/DeepHat-V1-7B",
    device="auto",
    use_remote=False
)

# Remote deployment
interface_remote = DeepHatInterface(
    model_name="DeepHat/DeepHat-V1-7B",
    use_remote=True,
    hf_api_token="your_token_here"
)

# Generate response with progress
response = interface.generate_response(
    prompt="Analyze this code...",
    show_progress=True
)
```

### DeepHatConfig

Enhanced configuration with new options:

```python
from zeroday.agents.deephat_security_agent import DeepHatConfig

config = DeepHatConfig(
    # Existing options
    model_name="DeepHat/DeepHat-V1-7B",
    device="auto",
    temperature=0.1,
    
    # New remote options
    use_remote=False,  # True for remote deployment
    hf_api_token=None,  # HF API token for remote
    remote_endpoint=None,  # Custom endpoint URL
    
    # New progress option
    show_progress=True  # Enable progress tracking
)
```

## 🚀 Performance Comparison

| Feature | Local Deployment | Remote Deployment |
|---------|-----------------|-------------------|
| **Setup Time** | 2-10 minutes (model download) | < 30 seconds |
| **Memory Usage** | ~15GB | Minimal |
| **Analysis Speed** | Fast (depends on hardware) | Medium (network dependent) |
| **Privacy** | Complete | Data sent to HF servers |
| **Cost** | Hardware only | API usage based |
| **Offline Support** | ✅ Yes | ❌ No |

## 🛠️ Troubleshooting

### Remote Mode Issues:

1. **403 Forbidden Error:**
   - Check that your HF API token is valid
   - Ensure token has read permissions

2. **503 Service Unavailable:**
   - Model may be loading on HF servers
   - Wait 2-5 minutes and retry

3. **Timeout Errors:**
   - Check internet connection
   - Try reducing `max_new_tokens` parameter

### Local Mode Issues:

1. **CUDA Out of Memory:**
   - Use `device="cpu"` for CPU-only inference
   - Reduce `max_new_tokens` parameter

2. **Model Download Fails:**
   - Check disk space (need ~15GB free)
   - Verify internet connection
   - Try clearing HF cache: `rm -rf ~/.cache/huggingface/`

## 🔮 Future Enhancements

Planned features for future releases:

- **Custom Endpoints**: Support for private model deployments
- **Batch Processing**: Analyze multiple files in parallel
- **Progress Persistence**: Save/resume analysis progress
- **Model Switching**: Easy switching between different DeepHat model versions
- **Performance Metrics**: Detailed timing and performance statistics