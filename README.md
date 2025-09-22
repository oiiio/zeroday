# 🔒 ZeroDay Pipeline

**Multi-agent zero-day vulnerability detection pipeline using NVIDIA NeMo Agent Toolkit and DeepHat-V1-7B**

AI-powered security analysis system that combines static analysis, pattern detection, and advanced LLM-based vulnerability detection to identify potential zero-day vulnerabilities in Python repositories.

## 🌟 Features

- **🤖 Multi-Agent Architecture**: Coordinated pipeline with specialized agents for different analysis tasks
- **🧠 DeepHat-V1-7B Integration**: Advanced cybersecurity-focused LLM for vulnerability detection
- **🔍 Zero-Day Detection**: Novel pattern recognition for previously unknown vulnerabilities
- **📊 Comprehensive Reporting**: Multiple output formats (JSON, HTML, TXT) with detailed analysis
- **⚡ Parallel Processing**: Concurrent analysis for improved performance
- **📈 Built-in Profiling**: NeMo Agent Toolkit integration with observability and performance monitoring
- **🎯 Python-Focused**: Specialized analysis for Python codebases and dependencies

## 🏗️ Architecture

The ZeroDay pipeline consists of four main agents orchestrated through the NVIDIA NeMo Agent Toolkit:

1. **Repository Ingestion Agent** - Clones and preprocesses GitHub repositories
2. **Python Analysis Agent** - Performs static analysis and pattern detection
3. **DeepHat Security Agent** - Advanced LLM-based vulnerability detection using DeepHat-V1-7B
4. **Report Generation Agent** - Consolidates findings and generates comprehensive reports

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   Repository    │───▶│   Python         │───▶│   DeepHat Security  │───▶│   Report            │
│   Ingestion     │    │   Analysis       │    │   Agent             │    │   Generation        │
│   Agent         │    │   Agent          │    │   (DeepHat-V1-7B)   │    │   Agent             │
└─────────────────┘    └──────────────────┘    └─────────────────────┘    └─────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- CUDA-compatible GPU (recommended for DeepHat model)
- Git
- 8GB+ RAM (16GB+ recommended)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/oiiio/zeroday.git
cd zeroday
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Set up environment variables:**
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Install optional dependencies for enhanced analysis:**
```bash
pip install -e .[analysis,viz]
```

### Basic Usage

**Analyze a single repository:**
```bash
python scripts/run_analysis.py https://github.com/user/repo
```

**Specify output directory:**
```bash
python scripts/run_analysis.py https://github.com/user/repo --output-dir ./my_reports
```

**Programmatic usage:**
```python
import asyncio
from zeroday.workflows.vulnerability_detection_workflow import VulnerabilityDetectionWorkflow

async def analyze_repo():
    workflow = VulnerabilityDetectionWorkflow()
    # Note: Requires proper NeMo Builder initialization
    result = await workflow.analyze_repository("https://github.com/user/repo")
    print(f"Found {result['vulnerabilities_found']} vulnerabilities")

asyncio.run(analyze_repo())
```

## 📋 Configuration

### Environment Variables

Key environment variables in `.env`:

```bash
# DeepHat Model Configuration
DEEPHAT_MODEL_NAME=DeepHat/DeepHat-V1-7B
DEEPHAT_DEVICE=auto
DEEPHAT_TORCH_DTYPE=auto

# Repository Analysis Settings
MAX_REPO_SIZE_MB=500
MAX_FILE_SIZE_KB=100
ANALYSIS_TIMEOUT_SECONDS=300

# Output Configuration
REPORTS_OUTPUT_DIR=./data/reports
ENABLE_PROFILING=true
```

### Agent Configuration

Each agent can be configured independently:

- **Repository Ingestion**: Size limits, file filters, clone depth
- **Python Analysis**: AST analysis, pattern matching, dangerous function detection
- **DeepHat Security**: Model parameters, context length, zero-day detection settings
- **Report Generation**: Output formats, code snippet inclusion, styling

## 🔍 Vulnerability Detection

The pipeline detects various types of vulnerabilities:

### Static Analysis
- Dangerous function calls (`eval`, `exec`, `subprocess`, etc.)
- Hardcoded credentials and secrets
- SQL injection patterns
- Command injection vulnerabilities
- Unsafe deserialization

### LLM-Based Analysis (DeepHat)
- Code injection vulnerabilities
- Authentication/authorization bypasses
- Cryptographic weaknesses
- Business logic flaws
- **Zero-day pattern detection**

### Zero-Day Detection
Advanced pattern recognition for:
- Novel attack vectors
- Complex logic flaws
- Subtle race conditions
- Unconventional library usage
- Business logic vulnerabilities

## 📊 Reports

Generated reports include:

- **Executive Summary**: Risk level, vulnerability counts, affected files
- **Detailed Findings**: Each vulnerability with severity, confidence, and recommendations
- **Risk Assessment**: Overall risk scoring and prioritization
- **Remediation Guidance**: Specific recommendations for fixing vulnerabilities

### Report Formats

- **JSON**: Machine-readable format for integration
- **HTML**: Rich visual reports with styling and charts
- **TXT**: Plain text reports for command-line usage

## 🛠️ Development

### Project Structure

```
zeroday/
├── agents/                 # Multi-agent implementations
│   ├── base_agent.py      # Base agent with NeMo integration
│   ├── orchestration_agent.py
│   ├── repo_ingestion_agent.py
│   ├── python_analysis_agent.py
│   ├── deephat_security_agent.py
│   └── report_generation_agent.py
├── workflows/             # NeMo workflow definitions
├── tools/                 # Utility tools and interfaces
├── configs/               # Configuration files
└── scripts/               # Utility scripts
```

### Running Tests

```bash
pytest tests/
```

### Code Quality

```bash
# Format code
black zeroday/

# Type checking
mypy zeroday/

# Linting
flake8 zeroday/
```

## 🔧 Advanced Usage

### Batch Analysis

Analyze multiple repositories:

```python
from zeroday.workflows.vulnerability_detection_workflow import VulnerabilityDetectionWorkflow

workflow = VulnerabilityDetectionWorkflow()
repos = [
    "https://github.com/user/repo1",
    "https://github.com/user/repo2",
    "https://github.com/user/repo3"
]

result = await workflow.analyze_repositories_batch(repos, max_concurrent=2)
```

### Custom Agent Configuration

```python
from zeroday.agents.deephat_security_agent import DeepHatConfig

custom_config = DeepHatConfig(
    name="custom_deephat",
    model_name="DeepHat/DeepHat-V1-7B",
    temperature=0.05,  # Lower temperature for more focused analysis
    max_context_length=65536,  # Larger context for big files
    enable_zero_day_detection=True,
    vulnerability_confidence_threshold=0.8
)
```

### Integration with CI/CD

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run ZeroDay Analysis
        run: |
          python scripts/run_analysis.py ${{ github.server_url }}/${{ github.repository }}
          # Process results and create security report
```

## 📈 Performance & Profiling

The pipeline includes built-in profiling via NeMo Agent Toolkit:

- **Token Usage Tracking**: Monitor LLM token consumption
- **Execution Time Analysis**: Identify bottlenecks in the pipeline
- **Agent Performance Metrics**: Individual agent execution statistics
- **Memory Usage Monitoring**: Track resource consumption

Access profiling data through the generated reports or NeMo's observability tools.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **NVIDIA NeMo Agent Toolkit** - Multi-agent orchestration and profiling
- **DeepHat Team** - Advanced cybersecurity LLM model
- **Hugging Face** - Model hosting and transformers library
- **Security Research Community** - Vulnerability patterns and detection techniques

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/oiiio/zeroday/issues)
- **Discussions**: [GitHub Discussions](https://github.com/oiiio/zeroday/discussions)
- **Documentation**: [Wiki](https://github.com/oiiio/zeroday/wiki)

---

**⚠️ Disclaimer**: This tool is for security research and authorized testing only. Users are responsible for ensuring compliance with applicable laws and regulations.
