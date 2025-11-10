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

##  Example .env
```bash
# ---------- Nessus connection ----------
NESSUS_URL=https://localhost:8834
VERIFY_SSL=true

# Preferred auth: API Keys (Settings → My Account → API Keys)
NESSUS_ACCESS_KEY=
NESSUS_SECRET_KEY=

# Fallback: username/password (only used if keys are empty)
NESSUS_USERNAME=
NESSUS_PASSWORD=

# Output directory
OUTPUT_DIR=outputs

# ---------- Optional AI settings ----------
AI_PROVIDER=
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
OPENAI_BASE_URL=https://api.openai.com/v1
DEEPSEEK_API_KEY=
DEEPSEEK_MODEL=deepseek-chat
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1

# ---------- Optional screenshots ----------
SCREENSHOTS_ENABLE=false
CHROME_PATH=/usr/bin/google-chrome
CHROMEDRIVER_PATH=/usr/local/bin/chromedriver
SCREENSHOT_WIDTH=1600
SCREENSHOT_HEIGHT=2000
```

## License
This project is licensed under the MIT License.
