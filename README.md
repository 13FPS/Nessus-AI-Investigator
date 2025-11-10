# Nessus AI Investigator

**Description:** Enables AI-powered analysis in Nessus Professional to provide intelligent vulnerability summaries, remediation guidance, and automated report generation.

## Features
- Browse Nessus folders and scans interactively  
- Retrieve vulnerabilities, severities, and solutions  
- Integrate AI (OpenAI GPT‑4o / DeepSeek) for remediation insights  
- Export HTML/PDF reports and generate Markdown summaries  
- Optional screenshots from exported reports  

## Installation
```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env for Nessus URL, credentials, and API keys
python3 nessus_ai_investigator_full.py
```

## License
This project is licensed under the MIT License.
