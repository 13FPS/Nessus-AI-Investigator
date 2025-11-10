#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nessus AI Investigator (Full, Working)"""
import os, sys, time, json, textwrap
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import requests
from requests.exceptions import RequestException
import urllib3
from dotenv import load_dotenv
from rich import print
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel

def _try_import_selenium():
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        return webdriver, Options
    except Exception:
        return None, None

load_dotenv()

NESSUS_URL = os.getenv('NESSUS_URL', 'https://localhost:8834').rstrip('/')
VERIFY_SSL = os.getenv('VERIFY_SSL', 'true').lower() == 'true'
NESSUS_ACCESS_KEY = os.getenv('NESSUS_ACCESS_KEY', '').strip()
NESSUS_SECRET_KEY = os.getenv('NESSUS_SECRET_KEY', '').strip()
NESSUS_USERNAME   = os.getenv('NESSUS_USERNAME', '').strip()
NESSUS_PASSWORD   = os.getenv('NESSUS_PASSWORD', '').strip()
OUTPUT_DIR = Path(os.getenv('OUTPUT_DIR', 'outputs'))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

AI_PROVIDER_DEFAULT = os.getenv('AI_PROVIDER', '').strip().lower()
OPENAI_API_KEY   = os.getenv('OPENAI_API_KEY', '').strip()
OPENAI_MODEL     = os.getenv('OPENAI_MODEL', 'gpt-4o-mini').strip()
OPENAI_BASE_URL  = os.getenv('OPENAI_BASE_URL', 'https://api.openai.com/v1').rstrip('/')
DEEPSEEK_API_KEY  = os.getenv('DEEPSEEK_API_KEY', '').strip()
DEEPSEEK_MODEL    = os.getenv('DEEPSEEK_MODEL', 'deepseek-chat').strip()
DEEPSEEK_BASE_URL = os.getenv('DEEPSEEK_BASE_URL', 'https://api.deepseek.com/v1').rstrip('/')

SCREENSHOTS_ENABLE = os.getenv('SCREENSHOTS_ENABLE', 'false').lower() == 'true'
CHROME_PATH        = os.getenv('CHROME_PATH', '').strip()
CHROMEDRIVER_PATH  = os.getenv('CHROMEDRIVER_PATH', '').strip()
SCREEN_WIDTH       = int(os.getenv('SCREENSHOT_WIDTH', '1600'))
SCREEN_HEIGHT      = int(os.getenv('SCREENSHOT_HEIGHT', '2000'))

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

def rich_table(title: str, columns: List[str]) -> Table:
    t = Table(title=title, show_lines=True, title_style='bold')
    for col in columns:
        t.add_column(col, overflow='fold')
    return t

def safe_get(d: Dict, *keys, default=None):
    cur = d
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur

@dataclass
class NessusClient:
    base_url: str
    verify_ssl: bool = True
    access_key: str = ''
    secret_key: str = ''
    username: str = ''
    password: str = ''
    token: Optional[str] = None

    def _headers(self) -> Dict[str, str]:
        hdrs = {'Content-Type': 'application/json'}
        if self.access_key and self.secret_key:
            hdrs['X-ApiKeys'] = f'accessKey={self.access_key}; secretKey={self.secret_key}'
        elif self.token:
            hdrs['X-Cookie'] = f'token={self.token}'
        return hdrs

    def login(self) -> None:
        if self.access_key and self.secret_key:
            return
        if not (self.username and self.password):
            raise RuntimeError('No Nessus credentials provided. Set API keys or username/password in .env')
        url = f'{self.base_url}/session'
        r = requests.post(url, json={'username': self.username, 'password': self.password}, verify=self.verify_ssl)
        r.raise_for_status()
        self.token = r.json().get('token')

    def folders(self) -> List[Dict[str, Any]]:
        url = f'{self.base_url}/folders'
        r = requests.get(url, headers=self._headers(), verify=self.verify_ssl)
        r.raise_for_status()
        return r.json().get('folders', [])

    def scans(self) -> List[Dict[str, Any]]:
        url = f'{self.base_url}/scans'
        r = requests.get(url, headers=self._headers(), verify=self.verify_ssl)
        r.raise_for_status()
        return r.json().get('scans', [])

    def scans_in_folder(self, folder_id: int) -> List[Dict[str, Any]]:
        return [s for s in self.scans() if s.get('folder_id') == folder_id]

    def scan_details(self, scan_id: int) -> Dict[str, Any]:
        url = f'{self.base_url}/scans/{scan_id}'
        r = requests.get(url, headers=self._headers(), verify=self.verify_ssl)
        r.raise_for_status()
        return r.json()

    def plugin_details(self, plugin_id: int) -> Dict[str, Any]:
        for path in (f'/plugins/plugin/{plugin_id}', f'/plugins/{plugin_id}'):
            url = f'{self.base_url}{path}'
            r = requests.get(url, headers=self._headers(), verify=self.verify_ssl)
            if r.status_code == 200:
                return r.json()
        return {}

    def _latest_history_id(self, scan_id: int) -> Optional[int]:
        try:
            details = self.scan_details(scan_id)
            histories = details.get('history', []) or details.get('histories', [])
            if not histories:
                return None
            def hist_key(h): return h.get('last_modification_date', 0)
            chosen = None
            for status in ('completed', 'imported', 'canceled'):
                cand = [h for h in histories if h.get('status') == status]
                if cand:
                    chosen = sorted(cand, key=hist_key, reverse=True)[0]
                    break
            if not chosen:
                chosen = sorted(histories, key=hist_key, reverse=True)[0]
            return chosen.get('history_id')
        except Exception:
            return None

    def export_scan(self, scan_id: int, fmt: str = 'pdf', chapters: Optional[str] = None) -> bytes:
        assert fmt in ('pdf', 'html')
        url = f'{self.base_url}/scans/{scan_id}/export'
        payload = {'format': fmt}
        hist = self._latest_history_id(scan_id)
        if hist:
            payload['history_id'] = hist
        if fmt in ('pdf', 'html'):
            payload['chapters'] = chapters or 'vuln_by_host,vuln_by_plugin,remediations'
        r = requests.post(url, headers=self._headers(), json=payload, verify=self.verify_ssl)
        if r.status_code == 400:
            raise RuntimeError(f"Export rejected (400). Ensure the run is 'completed' and chapters are valid. Payload: {payload}")
        r.raise_for_status()
        file_id = r.json().get('file')
        status_url = f'{self.base_url}/scans/{scan_id}/export/{file_id}/status'
        download_url = f'{self.base_url}/scans/{scan_id}/export/{file_id}/download'
        for _ in range(90):
            s = requests.get(status_url, headers=self._headers(), verify=self.verify_ssl)
            s.raise_for_status()
            if s.json().get('status') == 'ready':
                break
            time.sleep(2)
        else:
            raise RuntimeError('Export did not become ready in time')
        d = requests.get(download_url, headers=self._headers(), verify=self.verify_ssl)
        d.raise_for_status()
        return d.content

class AIProvider:
    def summarize(self, text: str, model: Optional[str] = None) -> str:
        raise NotImplementedError

class OpenAIProvider(AIProvider):
    def __init__(self, api_key: str, base_url: str):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
    def summarize(self, text: str, model: Optional[str] = None) -> str:
        model = model or OPENAI_MODEL
        url = f'{self.base_url}/chat/completions'
        headers = {'Authorization': f'Bearer {self.api_key}', 'Content-Type': 'application/json'}
        prompt = (
            'You are a security assistant. Read the vulnerability details and produce:\n'
            '- a short plain-language summary (1-2 sentences)\n'
            '- likely impact and affected components\n'
            '- concrete remediation steps (with commands/config examples if relevant)\n'
            'Be concise and actionable.\n\n'
            f'Vulnerability details:\n{text}'
        )
        payload = {
            'model': model,
            'messages': [
                {'role': 'system', 'content': 'You are a helpful cybersecurity analyst.'},
                {'role': 'user', 'content': prompt},
            ],
            'temperature': 0.2,
        }
        r = requests.post(url, headers=headers, json=payload, timeout=60)
        r.raise_for_status()
        data = r.json()
        return data['choices'][0]['message']['content'].strip()

class DeepSeekProvider(AIProvider):
    def __init__(self, api_key: str, base_url: str):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
    def summarize(self, text: str, model: Optional[str] = None) -> str:
        model = model or DEEPSEEK_MODEL
        url = f'{self.base_url}/chat/completions'
        headers = {'Authorization': f'Bearer {self.api_key}', 'Content-Type': 'application/json'}
        payload = {
            'model': model,
            'messages': [
                {'role': 'system', 'content': 'You are a helpful cybersecurity analyst.'},
                {'role': 'user', 'content': f'Summarize and provide remediation for:\n{text}'},
            ],
            'temperature': 0.2,
        }
        r = requests.post(url, headers=headers, json=payload, timeout=60)
        r.raise_for_status()
        data = r.json()
        return data['choices'][0]['message']['content'].strip()

def choose_ai_provider_interactive(default_choice: str) -> Optional[AIProvider]:
    options = ['none', 'openai', 'deepseek']
    choice = Prompt.ask('[bold]Select AI provider[/bold]', choices=options, default=(default_choice if default_choice in options else 'none'))
    if choice == 'openai':
        api_key = os.getenv('OPENAI_API_KEY') or Prompt.ask('Enter OpenAI API Key')
        return OpenAIProvider(api_key=api_key, base_url=OPENAI_BASE_URL)
    elif choice == 'deepseek':
        api_key = os.getenv('DEEPSEEK_API_KEY') or Prompt.ask('Enter DeepSeek API Key')
        return DeepSeekProvider(api_key=api_key, base_url=DEEPSEEK_BASE_URL)
    else:
        console.print('[yellow]AI disabled.[/yellow]'); return None

def pick_folder(nc: NessusClient) -> Optional[Dict[str, Any]]:
    folders = nc.folders()
    if not folders:
        console.print('[red]No folders found.[/red]'); return None
    table = rich_table('Nessus Folders', ['#', 'ID', 'Name', 'Unread'])
    for idx, f in enumerate(folders, start=1):
        table.add_row(str(idx), str(f.get('id')), f.get('name',''), str(f.get('unread_count',0)))
    console.print(table)
    choice = IntPrompt.ask('Select folder #', choices=[str(i) for i in range(1, len(folders)+1)])
    return folders[int(choice)-1]

def pick_scan(nc: NessusClient, folder_id: int) -> Optional[Dict[str, Any]]:
    scans = nc.scans_in_folder(folder_id)
    if not scans:
        console.print('[red]No scans in this folder.[/red]'); return None
    scans = sorted(scans, key=lambda s: s.get('last_modification_date', 0), reverse=True)
    table = rich_table('Scans in Folder', ['#', 'ID', 'Name', 'Status', 'Last Modified'])
    for idx, s in enumerate(scans, start=1):
        table.add_row(str(idx), str(s.get('id')), s.get('name',''), s.get('status',''), str(s.get('last_modification_date','')))
    console.print(table)
    choice = IntPrompt.ask('Select scan #', choices=[str(i) for i in range(1, len(scans)+1)])
    return scans[int(choice)-1]

def collect_vuln_data(nc: NessusClient, scan_id: int) -> List[Dict[str, Any]]:
    details = nc.scan_details(scan_id)
    vulns = details.get('vulnerabilities', [])
    results = []
    plugin_solution_cache: Dict[int, str] = {}
    for v in vulns:
        pid = v.get('plugin_id')
        solution = ''
        if pid:
            if pid in plugin_solution_cache:
                solution = plugin_solution_cache[pid]
            else:
                pd = nc.plugin_details(int(pid))
                solution = (safe_get(pd, 'info', 'solution') or safe_get(pd, 'plugin', 'solution') or '')
                plugin_solution_cache[pid] = solution
        results.append({
            'plugin_id': v.get('plugin_id'),
            'plugin_name': v.get('plugin_name'),
            'severity': v.get('severity'),
            'instances': v.get('count', 0),
            'solution': solution,
        })
    return results

def show_vuln_table(vulns: List[Dict[str, Any]]) -> None:
    if not vulns:
        console.print('[green]No vulnerabilities found.[/green]'); return
    vulns_sorted = sorted(vulns, key=lambda x: (x.get('severity', 0), x.get('instances', 0)), reverse=True)
    table = rich_table('Vulnerabilities (summary)', ['Plugin ID', 'Name', 'Severity', 'Instances', 'Solution (truncated)'])
    for v in vulns_sorted:
        sol = (v.get('solution') or '').strip()
        if len(sol) > 120: sol = sol[:117] + '...'
        table.add_row(str(v.get('plugin_id')), v.get('plugin_name',''), str(v.get('severity')), str(v.get('instances')), sol or '-')
    console.print(table)

def ai_enrich(vulns: List[Dict[str, Any]], ai: AIProvider) -> List[Dict[str, Any]]:
    enriched = []
    with Progress() as progress:
        task = progress.add_task('AI analyzing...', total=len(vulns))
        for v in vulns:
            ctx = json.dumps({
                'plugin_id': v['plugin_id'],
                'plugin_name': v['plugin_name'],
                'severity': v['severity'],
                'instances': v['instances'],
                'solution_from_nessus': v.get('solution','')
            }, indent=2)
            try:
                summary = ai.summarize(ctx)
            except Exception as e:
                summary = f'[AI error] {e}'
            enriched.append({**v, 'ai_summary': summary})
            progress.update(task, advance=1)
    return enriched

def export_report(nc: NessusClient, scan_id: int, fmt: str) -> Path:
    data = nc.export_scan(scan_id, fmt=fmt)
    out = OUTPUT_DIR / f'nessus_scan_{scan_id}.{fmt}'
    out.write_bytes(data)
    return out

def make_markdown(scan: Dict[str, Any], vulns: List[Dict[str, Any]], ai_used: Optional[str], html_path: Optional[Path], pdf_path: Optional[Path], screenshots: List[Path]) -> Path:
    md = OUTPUT_DIR / f"nessus_scan_{scan.get('id')}_summary.md"
    lines = []
    lines.append(f"# Nessus Scan Summary – {scan.get('name')} (ID: {scan.get('id')})\n")
    lines.append(f"- Status: {scan.get('status')}")
    lines.append(f"- Last Modified: {scan.get('last_modification_date')}")
    lines.append(f"- AI Provider: {ai_used or 'None'}")
    if html_path: lines.append(f"- HTML report: {html_path}")
    if pdf_path:  lines.append(f"- PDF report: {pdf_path}")
    if screenshots:
        lines.append('\n## Screenshots')
        for s in screenshots:
            lines.append(f"![Report Screenshot]({s})")
    lines.append('\n## Vulnerabilities')
    for v in sorted(vulns, key=lambda x: (x.get('severity', 0), x.get('instances', 0)), reverse=True):
        lines.append(f"""### {v.get('plugin_name')} (Plugin {v.get('plugin_id')}) – Severity {v.get('severity')}\n- Instances: {v.get('instances')}""")
        sol = (v.get('solution') or '').strip()
        if sol:
            lines.append('**Vendor Solution (from Nessus plugin):**\n')
            lines.append(textwrap.indent(sol, '> '))
        ai_sum = v.get('ai_summary')
        if ai_sum:
            lines.append('\n**AI Guidance:**\n')
            lines.append(textwrap.indent(ai_sum, '> '))
        lines.append('\n---')
    md.write_text('\n'.join(lines), encoding='utf-8')
    return md

def try_screenshot_html(html_path: Path, out_dir: Path) -> List[Path]:
    shots: List[Path] = []
    if not SCREENSHOTS_ENABLE:
        return shots
    webdriver, Options = _try_import_selenium()
    if not webdriver or not Options:
        console.print('[yellow]Screenshots requested, but selenium is not installed. Skipping.[/yellow]')
        return shots
    if not (CHROME_PATH and CHROMEDRIVER_PATH and Path(CHROME_PATH).exists() and Path(CHROMEDRIVER_PATH).exists()):
        console.print('[yellow]Screenshots requested, but Chrome/Chromedriver paths are not set or not found. Skipping.[/yellow]')
        return shots
    opts = Options()
    opts.binary_location = CHROME_PATH
    opts.add_argument('--headless=new')
    opts.add_argument(f'--window-size={SCREEN_WIDTH},{SCREEN_HEIGHT}')
    driver = webdriver.Chrome(executable_path=CHROMEDRIVER_PATH, options=opts)
    try:
        url = f'file://{html_path.resolve()}'
        driver.get(url)
        time.sleep(2)
        shot1 = out_dir / f'{html_path.stem}_page1.png'
        driver.save_screenshot(str(shot1))
        shots.append(shot1)
    finally:
        driver.quit()
    return shots

def main():
    console.print(Panel.fit('[bold cyan]Nessus AI Investigator (Full)[/bold cyan]'))
    nc = NessusClient(
        base_url=NESSUS_URL,
        verify_ssl=VERIFY_SSL,
        access_key=NESSUS_ACCESS_KEY,
        secret_key=NESSUS_SECRET_KEY,
        username=NESSUS_USERNAME,
        password=NESSUS_PASSWORD,
    )
    if not (NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY):
        console.print('[yellow]Using username/password auth. API Keys are recommended.[/yellow]')
        nc.login()

    folder = pick_folder(nc)
    if not folder: sys.exit(1)
    scan = pick_scan(nc, folder_id=folder['id'])
    if not scan: sys.exit(1)

    console.print('[cyan]Collecting vulnerability data + remediation (solution) ...[/cyan]')
    vulns = collect_vuln_data(nc, scan_id=scan['id'])
    show_vuln_table(vulns)

    ai_provider = choose_ai_provider_interactive(AI_PROVIDER_DEFAULT)
    ai_used = None
    if ai_provider and Confirm.ask('Run AI to enrich remediation/summary?'):
        ai_used = ai_provider.__class__.__name__.replace('Provider','')
        vulns = ai_enrich(vulns, ai_provider)

    html_path = None
    pdf_path = None
    if Confirm.ask('Export official HTML report?'):
        try:
            html_bytes = nc.export_scan(scan_id=scan['id'], fmt='html')
            html_path = OUTPUT_DIR / f"nessus_scan_{scan['id']}.html"
            html_path.write_bytes(html_bytes)
            console.print(f'[green]Exported:[/green] {html_path}')
        except Exception as e:
            console.print(f'[red]HTML export failed:[/red] {e}')
    if Confirm.ask('Export official PDF report?'):
        try:
            pdf_bytes = nc.export_scan(scan_id=scan['id'], fmt='pdf')
            pdf_path = OUTPUT_DIR / f"nessus_scan_{scan['id']}.pdf"
            pdf_path.write_bytes(pdf_bytes)
            console.print(f'[green]Exported:[/green] {pdf_path}')
        except Exception as e:
            console.print(f'[red]PDF export failed:[/red] {e}')

    screenshots = []
    if html_path and Confirm.ask('Capture screenshots from the exported HTML? (requires Chrome+Chromedriver)'):
        screenshots = try_screenshot_html(html_path, OUTPUT_DIR)
        if screenshots:
            console.print(f"[green]Saved screenshots:[/green] {', '.join(map(str, screenshots))}")
        else:
            console.print('[yellow]No screenshots created.[/yellow]')

    if Confirm.ask('Generate a Markdown summary with solutions (and screenshots if any)?'):
        md_path = make_markdown(scan, vulns, ai_used, html_path, pdf_path, screenshots)
        console.print(f'[green]Wrote summary:[/green] {md_path}')
    console.print('[bold green]Done.[/bold green]')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.print('\n[red]Interrupted by user[/red]\n')
