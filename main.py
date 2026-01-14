import sys
import os
import subprocess
import ctypes

# --- STEP 0: DEPENDENCY CHECKER & AUTO INSTALL ---
def check_and_install_dependencies():
    required_packages = [
        ('PyQt5', 'PyQt5'),
        ('psutil', 'psutil'),
        ('asyncssh', 'asyncssh'),
        ('cryptography', 'cryptography') # THÊM MỚI: Thư viện bảo mật
    ]
    
    missing = []
    for import_name, install_name in required_packages:
        try:
            __import__(import_name)
        except ImportError:
            missing.append(install_name)

    if missing:
        MB_YESNO = 0x04
        MB_ICONQUESTION = 0x20
        title = "Thiếu thư viện hỗ trợ"
        message = (f"Chương trình phát hiện thiếu các gói sau: {', '.join(missing)}.\n"
                   "Bạn có muốn tự động tải và cài đặt chúng ngay bây giờ không?\n"
                   "(Chương trình sẽ tự khởi động lại sau khi cài xong)")
        
        response = ctypes.windll.user32.MessageBoxW(0, message, title, MB_YESNO | MB_ICONQUESTION)
        
        if response == 6: # IDYES = 6
            print("Đang cài đặt các gói thiếu...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
                print("Cài đặt hoàn tất! Đang khởi động lại...")
                os.execv(sys.executable, ['python'] + sys.argv)
            except Exception as e:
                ctypes.windll.user32.MessageBoxW(0, f"Lỗi khi cài đặt: {e}", "Lỗi", 0x10)
                sys.exit(1)
        else:
            sys.exit(0)

check_and_install_dependencies()

# --- IMPORTS ---
import time
import socket
import random
import json
import psutil
import base64
import asyncio
import winreg
import asyncssh
import ssl
import statistics
import atexit 
import uuid
import hashlib
import urllib.request 
from urllib.request import Request, build_opener, ProxyHandler
from urllib.error import URLError
from cryptography.fernet import Fernet # NEW IMPORT

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QCheckBox, 
                             QGroupBox, QTextEdit, QHBoxLayout, QSystemTrayIcon, 
                             QMenu, QAction, QStyle, QComboBox, 
                             QDialog, QTableWidget, QTableWidgetItem, QHeaderView, 
                             QMessageBox, QRadioButton, QStackedWidget, QAbstractItemView,
                             QSizePolicy, QSpinBox, QGridLayout, QListWidget, QFrame, QScrollArea,
                             QTabWidget, QColorDialog, QFontComboBox)
from PyQt5.QtCore import QThread, pyqtSignal, QSettings, Qt, QTimer
from PyQt5.QtGui import QTextCursor, QIcon, QPixmap, QColor, QFont, QPalette

# --- UTILS & SECURITY ---
def resource_path(relative_path):
    try: base_path = sys._MEIPASS
    except Exception: base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

def get_config_path(filename):
    if getattr(sys, 'frozen', False): application_path = os.path.dirname(sys.executable)
    else: application_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(application_path, filename)

# === NEW SECURITY IMPLEMENTATION ===
class SecurityManager:
    _cipher = None

    @staticmethod
    def get_cipher():
        if SecurityManager._cipher is None:
            # Tạo Key dựa trên Machine ID (UUID) + Salt cứng
            # Điều này khiến file settings.ini chỉ giải mã được trên máy tính này
            machine_fingerprint = str(uuid.getnode()) + "SSH_PROXY_V2_SALT_2025"
            key = base64.urlsafe_b64encode(hashlib.sha256(machine_fingerprint.encode()).digest())
            SecurityManager._cipher = Fernet(key)
        return SecurityManager._cipher

def encrypt_text(text):
    try:
        if not text: return ""
        cipher = SecurityManager.get_cipher()
        return cipher.encrypt(text.encode()).decode()
    except Exception as e:
        print(f"Encrypt error: {e}")
        return text

def decrypt_text(text):
    try:
        if not text: return "[]"
        cipher = SecurityManager.get_cipher()
        return cipher.decrypt(text.encode()).decode()
    except Exception:
        return "[]" # Trả về list rỗng nếu lỗi (do file cũ hoặc sai máy)
# ===================================

def str2bool(v):
    if isinstance(v, bool): return v
    return str(v).lower() in ("yes", "true", "t", "1")

def format_speed(bytes_per_sec):
    if bytes_per_sec < 1024: return f"{bytes_per_sec:.0f} B/s"
    elif bytes_per_sec < 1024**2: return f"{bytes_per_sec/1024:.1f} KB/s"
    else: return f"{bytes_per_sec/1024**2:.1f} MB/s"

def format_size(size):
    power = 2**10
    n = 0
    power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power: size /= power; n += 1
    return f"{size:.2f} {power_labels[n]}B"

# --- SYSTEM PROXY MANAGER (IMPROVED STABILITY) ---
class SystemProxyManager:
    REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    
    @staticmethod
    def set_proxy(ip, port):
        try:
            settings = winreg.OpenKey(winreg.HKEY_CURRENT_USER, SystemProxyManager.REG_PATH, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(settings, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(settings, "ProxyServer", 0, winreg.REG_SZ, f"socks={ip}:{port}")
            winreg.CloseKey(settings)
            SystemProxyManager.refresh_system()
            return True
        except: return False

    @staticmethod
    def disable_proxy():
        """Force disable proxy safely"""
        try:
            settings = winreg.OpenKey(winreg.HKEY_CURRENT_USER, SystemProxyManager.REG_PATH, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(settings, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(settings)
            SystemProxyManager.refresh_system()
            # print("System Proxy Disabled.")
            return True
        except: return False

    @staticmethod
    def refresh_system():
        try:
            internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
            internet_set_option(0, 39, 0, 0)
            internet_set_option(0, 37, 0, 0)
        except: pass

# Đăng ký hàm này để chạy khi chương trình thoát bất ngờ (safety net)
atexit.register(SystemProxyManager.disable_proxy)

# --- GEOIP WORKER ---
class GeoIPWorker(QThread):
    info_signal = pyqtSignal(dict)
    SOURCES = {
        'ip-api.com': "http://ip-api.com/json/{ip}",
        'reallyfreegeoip.org': "https://reallyfreegeoip.org/json/{ip}",
        'freeipapi.com': "https://free.freeipapi.com/api/json/{ip}"
    }

    def __init__(self, ip, priority_list=None):
        super().__init__()
        self.ip = ip
        self.priority_list = priority_list if priority_list else ['ip-api.com', 'reallyfreegeoip.org', 'freeipapi.com']

    def parse_data(self, source, data):
        res = {'status': 'success', 'source': source}
        try:
            if source == 'ip-api.com':
                res['country'] = data.get('country', 'Unknown')
                res['city'] = data.get('city', 'Unknown')
                res['countryCode'] = data.get('countryCode', '').lower()
            elif source == 'reallyfreegeoip.org':
                res['country'] = data.get('country_name', 'Unknown')
                res['city'] = data.get('city', 'Unknown')
                res['countryCode'] = data.get('country_code', '').lower()
            elif source == 'freeipapi.com':
                res['country'] = data.get('countryName', 'Unknown')
                res['city'] = data.get('cityName', 'Unknown')
                res['countryCode'] = data.get('countryCode', '').lower()
            else: return None
            return res
        except: return None

    def run(self):
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        proxy_handler = ProxyHandler({}) 
        opener = build_opener(proxy_handler)
        for source in self.priority_list:
            if source not in self.SOURCES: continue
            url = self.SOURCES[source].format(ip=self.ip)
            try:
                req = Request(url, headers=headers)
                with opener.open(req, timeout=5) as response:
                    raw_data = response.read().decode()
                    parsed = self.parse_data(source, json.loads(raw_data))
                    if parsed:
                        self.info_signal.emit(parsed)
                        return
            except Exception: continue
        self.info_signal.emit({'status': 'fail', 'query': self.ip})

# --- NETWORK CHECKER WORKER ---
class NetworkChecker(QThread):
    info_signal = pyqtSignal(dict) 
    def __init__(self, proxy_port):
        super().__init__()
        self.proxy_port = int(proxy_port)
    
    def socks5_connect(self, target_host, target_port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(('127.0.0.1', self.proxy_port))
            s.sendall(b'\x05\x01\x00')
            if s.recv(2) != b'\x05\x00': s.close(); return None
            host_bytes = target_host.encode('utf-8')
            req = b'\x05\x01\x00\x03' + bytes([len(host_bytes)]) + host_bytes + target_port.to_bytes(2, 'big')
            s.sendall(req)
            resp = s.recv(4)
            if not resp or resp[1] != 0: s.close(); return None
            if resp[3] == 1: s.recv(6)
            elif resp[3] == 3: s.recv(1 + ord(s.recv(1)) + 2)
            elif resp[3] == 4: s.recv(18)
            return s
        except: return None

    def measure_ping_jitter(self):
        pings = []
        for _ in range(4): 
            start = time.time()
            s = self.socks5_connect('8.8.8.8', 53)
            if s:
                latency = (time.time() - start) * 1000
                pings.append(latency)
                s.close()
            time.sleep(0.15)
        if not pings: return "Timeout", "0 ms"
        avg_ping = statistics.mean(pings)
        jitter = statistics.stdev(pings) if len(pings) > 1 else 0.0
        return f"{avg_ping:.0f} ms", f"{jitter:.0f} ms"

    def run(self):
        p, j = self.measure_ping_jitter()
        self.info_signal.emit({'ping': p, 'jitter': j})

# --- NETWORK ENGINE (SMART LOAD BALANCING) ---
class NetworkEngine(QThread):
    log_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str)
    active_hosts_signal = pyqtSignal(list) 

    def __init__(self, main_port, targets, buffer_size=65536):
        super().__init__()
        self.main_port = int(main_port)
        self.targets = targets 
        self.buffer_size = buffer_size
        self.loop = None
        self.running = True
        self.active_backends = [] 
        self.backend_map = {} 
        self.active_hosts_set = set()
        
        # SMART LOAD BALANCING VARS
        self.backend_load = {} # {local_port: current_connection_count}

    def run(self):
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self.start_engine())
        except asyncio.CancelledError: pass
        except Exception as e:
            self.log_signal.emit(f"💥 Engine Crash: {e}")
        finally:
            self.clean_up_internal()
            if self.loop and not self.loop.is_closed(): self.loop.close()

    async def start_engine(self):
        self.log_signal.emit(f"🚀 Starting Engine on Port {self.main_port}...")
        base_port = 20000
        tasks = []
        for idx, target in enumerate(self.targets):
            local_port = base_port + idx + random.randint(1, 1000)
            self.backend_map[local_port] = target
            # Init load counter
            self.backend_load[local_port] = 0 
            tasks.append(asyncio.create_task(self.ssh_worker(target, local_port)))
        
        server = await asyncio.start_server(self.handle_client, '127.0.0.1', self.main_port)
        self.log_signal.emit(f"✅ Load Balancer Listening on 127.0.0.1:{self.main_port}")
        self.status_signal.emit(f"Running :{self.main_port}")
        async with server:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def ssh_worker(self, target, local_port):
        host = target['host']
        user = target['user']
        pwd = target['pass']
        ssh_port = int(target.get('ssh_port', 22))
        fail_count = 0
        while self.running:
            conn = None
            try:
                self.log_signal.emit(f"⏳ [{host}] Connecting...")
                conn = await asyncio.wait_for(
                    asyncssh.connect(host, username=user, password=pwd, known_hosts=None, port=ssh_port), 
                    timeout=8
                )
                self.log_signal.emit(f"🔗 [{host}] SSH Auth OK.")
                fail_count = 0
                listener = await conn.forward_socks('127.0.0.1', local_port)
                self.log_signal.emit(f"✅ [{host}] READY (Port {local_port})")
                
                if local_port not in self.active_backends: self.active_backends.append(local_port)
                if host not in self.active_hosts_set:
                    self.active_hosts_set.add(host)
                    self.active_hosts_signal.emit(list(self.active_hosts_set))

                await listener.wait_closed()
                await conn.wait_closed()

            except (asyncio.TimeoutError, asyncssh.Error, OSError) as e:
                if fail_count < 3: self.log_signal.emit(f"⚠️ [{host}] Fail: {str(e)}")
                fail_count += 1
            except asyncio.CancelledError: break
            except Exception as e:
                fail_count += 1
                self.log_signal.emit(f"⚠️ [{host}] Error: {str(e)}")
            finally:
                if local_port in self.active_backends: self.active_backends.remove(local_port)
                if host in self.active_hosts_set:
                    self.active_hosts_set.discard(host)
                    self.active_hosts_signal.emit(list(self.active_hosts_set))
                try: 
                    if conn: conn.close()
                except: pass
            
            if not self.running: break
            await asyncio.sleep(5)

    def get_next_backend(self):
        # === SMART LOAD BALANCING (LEAST CONNECTIONS) ===
        if not self.active_backends: return None
        
        # Tìm port có số lượng kết nối đang xử lý (load) thấp nhất
        # Filter active backends only
        candidates = [p for p in self.active_backends]
        if not candidates: return None
        
        # Sort by load (ascending)
        best_port = min(candidates, key=lambda p: self.backend_load.get(p, 0))
        return best_port

    async def handle_client(self, client_reader, client_writer):
        target_port = self.get_next_backend()
        if not target_port:
            client_writer.close()
            return
            
        # Tăng load counter
        self.backend_load[target_port] = self.backend_load.get(target_port, 0) + 1
        
        remote_reader = None
        remote_writer = None
        try:
            remote_reader, remote_writer = await asyncio.open_connection('127.0.0.1', target_port)
            await asyncio.gather(
                self.pipe(client_reader, remote_writer),
                self.pipe(remote_reader, client_writer)
            )
        except: pass
        finally:
            # Giảm load counter khi client ngắt kết nối
            if target_port in self.backend_load and self.backend_load[target_port] > 0:
                self.backend_load[target_port] -= 1
                
            try: 
                if remote_writer: remote_writer.close()
                client_writer.close()
            except: pass

    async def pipe(self, reader, writer):
        try:
            while self.running:
                data = await reader.read(self.buffer_size)
                if not data: break
                writer.write(data)
                await writer.drain()
        except: pass
        finally:
            try: writer.close()
            except: pass

    def clean_up_internal(self):
        try:
            pending = asyncio.all_tasks(self.loop)
            for task in pending: task.cancel()
            if pending: self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except: pass

    def stop(self):
        self.running = False
        if self.loop and not self.loop.is_closed():
            try: self.loop.call_soon_threadsafe(lambda: [t.cancel() for t in asyncio.all_tasks(self.loop)])
            except RuntimeError: pass
        self.quit()
        self.wait()

# --- DIALOGS (UNCHANGED) ---
class EditHostDialog(QDialog):
    def __init__(self, host_data, is_add_mode=False, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Thêm Tài Khoản Mới" if is_add_mode else "Chỉnh sửa Account")
        self.setModal(True)
        self.data = host_data
        self.is_add_mode = is_add_mode # Lưu trạng thái thêm mới hay sửa
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        
        # Host
        self.txt_host = QLineEdit(self.data.get('host', ''))
        self.txt_host.setPlaceholderText("Host IP")
        
        # User
        self.txt_user = QLineEdit(self.data.get('user', ''))
        self.txt_user.setPlaceholderText("User")
        
        # Password Area
        self.txt_pass = QLineEdit(self.data.get('pass', ''))
        self.txt_pass.setPlaceholderText("Password")
        self.txt_pass.setEchoMode(QLineEdit.Password)
        
        # Port
        self.txt_port = QLineEdit(str(self.data.get('ssh_port', '22')))
        self.txt_port.setPlaceholderText("SSH Port")
        self.txt_port.setValidator(None) # Cho phép nhập số

        # --- NÚT CON MẮT (SHOW PASSWORD) ---
        # Chỉ hiện khi đang THÊM MỚI (is_add_mode = True)
        h_pass_layout = QHBoxLayout()
        h_pass_layout.addWidget(self.txt_pass)
        
        if self.is_add_mode:
            self.btn_eye = QPushButton("👁")
            self.btn_eye.setCheckable(True)
            self.btn_eye.setFixedWidth(40)
            self.btn_eye.setToolTip("Hiện/Ẩn mật khẩu")
            self.btn_eye.clicked.connect(self.toggle_password_visibility)
            h_pass_layout.addWidget(self.btn_eye)
        # -----------------------------------

        btn_save = QPushButton("Lưu thay đổi")
        btn_save.clicked.connect(self.save_info)
        
        # Layout Assembly
        layout.addWidget(QLabel("Host IP:"))
        layout.addWidget(self.txt_host)
        
        row_up = QHBoxLayout()
        v1 = QVBoxLayout(); v1.addWidget(QLabel("User:")); v1.addWidget(self.txt_user)
        v2 = QVBoxLayout(); v2.addWidget(QLabel("SSH Port:")); v2.addWidget(self.txt_port)
        row_up.addLayout(v1); row_up.addLayout(v2)
        layout.addLayout(row_up)
        
        layout.addWidget(QLabel("Password:"))
        layout.addLayout(h_pass_layout) # Dùng layout chứa pass + nút mắt
        
        layout.addWidget(btn_save)
        self.setLayout(layout)

    def toggle_password_visibility(self):
        if self.btn_eye.isChecked():
            self.txt_pass.setEchoMode(QLineEdit.Normal)
            self.btn_eye.setText("🔒")
        else:
            self.txt_pass.setEchoMode(QLineEdit.Password)
            self.btn_eye.setText("👁")

    def save_info(self):
        self.data['host'] = self.txt_host.text().strip()
        self.data['user'] = self.txt_user.text().strip()
        self.data['pass'] = self.txt_pass.text().strip()
        try: self.data['ssh_port'] = int(self.txt_port.text().strip())
        except: self.data['ssh_port'] = 22
        self.accept()

class HistoryManager(QDialog):
    def __init__(self, history_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Quản lý Danh sách Server")
        self.resize(600, 400)
        self.history_data = history_data
        self.initUI()
        
    def initUI(self):
        layout = QVBoxLayout()
        self.table = QTableWidget(); self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Host IP", "Port", "User", "Hành động"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        layout.addWidget(self.table)
        
        btn_add = QPushButton("➕ Thêm mới")
        btn_add.clicked.connect(self.add_new)
        layout.addWidget(btn_add)
        
        btn_close = QPushButton("Đóng")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)
        
        self.setLayout(layout)
        self.load_data()
        
    def load_data(self):
        self.table.setRowCount(0)
        for row_idx, item in enumerate(self.history_data):
            self.table.insertRow(row_idx)
            self.table.setItem(row_idx, 0, QTableWidgetItem(item.get('host', '')))
            self.table.setItem(row_idx, 1, QTableWidgetItem(str(item.get('ssh_port', '22'))))
            self.table.setItem(row_idx, 2, QTableWidgetItem(item.get('user', '')))
            
            cell_widget = QWidget(); layout_cell = QHBoxLayout(cell_widget)
            layout_cell.setContentsMargins(0,0,0,0)
            
            btn_edit = QPushButton("🔧"); btn_edit.setFixedWidth(30)
            btn_edit.clicked.connect(lambda _, r=row_idx: self.edit_row(r))
            
            btn_del = QPushButton("❌"); btn_del.setFixedWidth(30)
            btn_del.clicked.connect(lambda _, r=row_idx: self.delete_row(r))
            
            layout_cell.addWidget(btn_edit); layout_cell.addWidget(btn_del)
            self.table.setCellWidget(row_idx, 3, cell_widget)
            
    def add_new(self):
        new_item = {"host": "", "user": "root", "pass": "", "ssh_port": 22}
        # Truyền is_add_mode=True để hiện con mắt
        if EditHostDialog(new_item, is_add_mode=True, parent=self).exec_() == QDialog.Accepted:
            if new_item['host']: self.history_data.insert(0, new_item); self.load_data()
            
    def edit_row(self, row_idx):
        # Truyền is_add_mode=False để ẨN con mắt (bảo mật pass cũ)
        if EditHostDialog(self.history_data[row_idx], is_add_mode=False, parent=self).exec_() == QDialog.Accepted: 
            self.load_data()
            
    def delete_row(self, row_idx):
        if QMessageBox.question(self, "Xác nhận", "Xoá Server này?", QMessageBox.Yes|QMessageBox.No) == QMessageBox.Yes:
            del self.history_data[row_idx]; self.load_data()

# --- SETTINGS TAB UI ---
class SettingsTab(QWidget):
    settings_saved = pyqtSignal(dict)
    def __init__(self, current_settings):
        super().__init__()
        self.current_settings = current_settings
        self.initUI()
    def initUI(self):
        layout = QVBoxLayout()
        grp_app = QGroupBox("Giao diện & Phông chữ")
        l_app = QGridLayout()
        l_app.addWidget(QLabel("Font chữ:"), 0, 0)
        self.font_box = QFontComboBox()
        cur_font = self.current_settings.get("font_family", "Segoe UI")
        self.font_box.setCurrentFont(QFont(cur_font))
        l_app.addWidget(self.font_box, 0, 1)
        l_app.addWidget(QLabel("Cỡ chữ:"), 1, 0)
        self.size_spin = QSpinBox()
        self.size_spin.setRange(8, 20)
        self.size_spin.setValue(int(self.current_settings.get("font_size", 9)))
        l_app.addWidget(self.size_spin, 1, 1)
        l_app.addWidget(QLabel("Màu nền (Window):"), 2, 0)
        self.btn_bg_color = QPushButton("Chọn màu")
        self.bg_color_val = self.current_settings.get("bg_color", "#f0f0f0")
        self.btn_bg_color.setStyleSheet(f"background-color: {self.bg_color_val}")
        self.btn_bg_color.clicked.connect(self.pick_bg_color)
        l_app.addWidget(self.btn_bg_color, 2, 1)
        l_app.addWidget(QLabel("Màu chữ (Text):"), 3, 0)
        self.btn_text_color = QPushButton("Chọn màu")
        self.text_color_val = self.current_settings.get("text_color", "#000000")
        self.btn_text_color.setStyleSheet(f"background-color: {self.text_color_val}")
        self.btn_text_color.clicked.connect(self.pick_text_color)
        l_app.addWidget(self.btn_text_color, 3, 1)
        grp_app.setLayout(l_app)
        layout.addWidget(grp_app)
        grp_geoip = QGroupBox("Ưu tiên công cụ kiểm tra IP (GeoIP)")
        l_geo = QVBoxLayout()
        l_geo.addWidget(QLabel("Kéo thả để sắp xếp thứ tự ưu tiên:"))
        self.list_geoip = QListWidget()
        self.list_geoip.setDragDropMode(QAbstractItemView.InternalMove)
        default_order = ["ip-api.com", "reallyfreegeoip.org", "freeipapi.com"]
        saved_order = self.current_settings.get("geoip_priority", default_order)
        final_order = [x for x in saved_order if x in default_order]
        for missing in default_order:
            if missing not in final_order: final_order.append(missing)
        self.list_geoip.addItems(final_order)
        l_geo.addWidget(self.list_geoip)
        grp_geoip.setLayout(l_geo)
        layout.addWidget(grp_geoip)
        self.btn_save = QPushButton("💾 LƯU CÀI ĐẶT")
        self.btn_save.setMinimumHeight(40)
        self.btn_save.setStyleSheet("background-color: #007bff; color: white; font-weight: bold;")
        self.btn_save.clicked.connect(self.save_clicked)
        layout.addWidget(self.btn_save)
        layout.addStretch()
        self.setLayout(layout)
    def pick_bg_color(self):
        c = QColorDialog.getColor(QColor(self.bg_color_val), self, "Chọn màu nền")
        if c.isValid():
            self.bg_color_val = c.name()
            self.btn_bg_color.setStyleSheet(f"background-color: {self.bg_color_val}")
    def pick_text_color(self):
        c = QColorDialog.getColor(QColor(self.text_color_val), self, "Chọn màu chữ")
        if c.isValid():
            self.text_color_val = c.name()
            self.btn_text_color.setStyleSheet(f"background-color: {self.text_color_val}")
    def save_clicked(self):
        geo_order = [self.list_geoip.item(i).text() for i in range(self.list_geoip.count())]
        new_conf = {
            "font_family": self.font_box.currentFont().family(),
            "font_size": self.size_spin.value(),
            "bg_color": self.bg_color_val,
            "text_color": self.text_color_val,
            "geoip_priority": geo_order
        }
        self.settings_saved.emit(new_conf)

# --- MAIN APP ---
class SSHProxyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # --- SELF HEALING PROXY ON STARTUP ---
        SystemProxyManager.disable_proxy() 
        # -------------------------------------

        self.setWindowTitle("SSH Proxy (Secure & Smart Balance)")
        self.setGeometry(300, 100, 520, 780) 
        
        icon_path = resource_path("logo.ico")
        if os.path.exists(icon_path): self.setWindowIcon(QIcon(icon_path))
        else: self.setWindowIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))

        ini_path = get_config_path("settings.ini")
        self.settings = QSettings(ini_path, QSettings.IniFormat)
        
        self.network_engine = None
        self.history_data = [] 
        self.connected_ips = []
        self.geoip_worker = None
        self.geoip_priority = []

        self.monitor_timer = QTimer(); self.monitor_timer.timeout.connect(self.update_stats)
        self.ping_check_timer = QTimer()
        self.ping_check_timer.setInterval(10000) 
        self.ping_check_timer.timeout.connect(self.trigger_ping_check)
        
        self.checker_thread = None
        self.start_time = 0; self.last_net_io = None; self.initial_net_io = None
        self.is_connected = False
        
        self.last_ping = "N/A"
        self.last_jitter = "N/A"

        self.initUI()
        self.initTray()
        self.load_config()

    def initUI(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.tab_home = QWidget()
        layout = QVBoxLayout(self.tab_home)

        mode_grp = QGroupBox("Chế độ hoạt động")
        mode_layout = QHBoxLayout()
        self.rad_single = QRadioButton("Single Server")
        self.rad_multi = QRadioButton("Multi Server (Smart Balancer)")
        self.rad_single.setChecked(True)
        self.rad_single.toggled.connect(self.toggle_mode_ui)
        mode_layout.addWidget(self.rad_single)
        mode_layout.addWidget(self.rad_multi)
        mode_grp.setLayout(mode_layout)
        layout.addWidget(mode_grp)

        self.stack_ui = QStackedWidget()
        self.page_single = QWidget()
        l_single = QVBoxLayout()
        l_single.setContentsMargins(0,0,0,0)
        row_host = QHBoxLayout()
        self.host_box = QComboBox(); self.host_box.setEditable(True)
        self.host_box.setPlaceholderText("Host IP")
        self.host_box.currentIndexChanged.connect(self.on_host_selected) 
        self.btn_manage = QPushButton("⚙️")
        self.btn_manage.setFixedWidth(35)
        self.btn_manage.clicked.connect(self.open_history_manager)
        row_host.addWidget(self.host_box); row_host.addWidget(self.btn_manage)
        self.user_box = QLineEdit(); self.user_box.setPlaceholderText("User")
        self.pwd = QLineEdit(); self.pwd.setEchoMode(QLineEdit.Password)
        self.pwd.setPlaceholderText("Password")
        
        grp_ssh_port = QWidget(); l_ssh_port = QHBoxLayout(grp_ssh_port); l_ssh_port.setContentsMargins(0,0,0,0)
        self.chk_custom_ssh_port = QCheckBox("Tuỳ chỉnh SSH Port")
        self.txt_ssh_port = QLineEdit("22"); self.txt_ssh_port.setFixedWidth(60); self.txt_ssh_port.setEnabled(False)
        self.chk_custom_ssh_port.toggled.connect(lambda c: self.txt_ssh_port.setEnabled(c))
        l_ssh_port.addWidget(self.chk_custom_ssh_port); l_ssh_port.addWidget(self.txt_ssh_port); l_ssh_port.addStretch()

        grp_single = QGroupBox("Thông tin Single Server")
        l_s = QVBoxLayout(); l_s.setContentsMargins(10, 10, 10, 10); l_s.setSpacing(5) 
        l_s.addLayout(row_host); l_s.addWidget(self.user_box); l_s.addWidget(self.pwd); l_s.addWidget(grp_ssh_port) 
        grp_single.setLayout(l_s); l_single.addWidget(grp_single)
        self.page_single.setLayout(l_single)

        self.page_multi = QWidget(); l_multi = QVBoxLayout(); l_multi.setContentsMargins(0,0,0,0)
        row_head_multi = QHBoxLayout()
        self.lbl_multi_hd = QLabel("Chọn servers:")
        self.btn_select_all = QPushButton("☑️ All"); self.btn_select_all.setFixedWidth(120)
        self.btn_select_all.clicked.connect(self.toggle_select_all)
        row_head_multi.addWidget(self.lbl_multi_hd); row_head_multi.addWidget(self.btn_select_all)

        self.table_multi = QTableWidget(); self.table_multi.setColumnCount(4)
        self.table_multi.setHorizontalHeaderLabels(["✔", "Host IP", "✔", "Host IP"])
        self.table_multi.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_multi.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table_multi.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_multi.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_multi.verticalHeader().setVisible(False)
        self.table_multi.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_multi.setMinimumHeight(150); self.table_multi.setMaximumHeight(160)
        
        btn_manage_multi = QPushButton("⚙️ Quản lý / Thêm tài khoản")
        btn_manage_multi.clicked.connect(self.open_history_manager)
        l_multi.addLayout(row_head_multi); l_multi.addWidget(self.table_multi); l_multi.addWidget(btn_manage_multi)
        self.page_multi.setLayout(l_multi)

        self.stack_ui.addWidget(self.page_single); self.stack_ui.addWidget(self.page_multi)
        layout.addWidget(self.stack_ui)

        grp2 = QGroupBox("Cấu hình Chung"); l2 = QVBoxLayout()
        row_params = QHBoxLayout()
        self.port = QLineEdit("10800"); self.chk_random_port = QCheckBox("Random Port")
        self.cmb_buffer = QComboBox(); self.cmb_buffer.addItems(["32KB", "64KB", "128KB", "256KB", "512KB"])
        self.cmb_buffer.setCurrentText("64KB")
        row_params.addWidget(QLabel("SOCKS Port:")); row_params.addWidget(self.port)
        row_params.addWidget(self.chk_random_port); row_params.addWidget(QLabel("Buffer:")); row_params.addWidget(self.cmb_buffer)
        l2.addLayout(row_params)

        self.chk_save = QCheckBox("Lưu Pass (Encrypted)"); self.chk_sys = QCheckBox("System Proxy")
        self.chk_tray = QCheckBox("Ẩn Tray"); self.chk_show_info = QCheckBox("Hiển thị thông tin Socks")
        self.chk_show_info.setChecked(True); self.chk_show_info.toggled.connect(self.toggle_info_display)

        grid_opts = QGridLayout()
        grid_opts.addWidget(self.chk_save, 0, 0); grid_opts.addWidget(self.chk_tray, 1, 0)
        grid_opts.addWidget(self.chk_sys, 0, 1); grid_opts.addWidget(self.chk_show_info, 1, 1)
        l2.addLayout(grid_opts); grp2.setLayout(l2); layout.addWidget(grp2)

        self.chk_random_port.stateChanged.connect(self.save_config)
        self.chk_save.stateChanged.connect(self.save_config)
        self.chk_sys.stateChanged.connect(self.save_config)
        self.chk_tray.stateChanged.connect(self.save_config)
        self.chk_show_info.stateChanged.connect(self.save_config)

        self.grp_net_status = QGroupBox("Network Status")
        grid_net = QGridLayout()
        grid_net.setColumnStretch(0, 3) 
        grid_net.setColumnStretch(1, 4)
        
        self.lbl_time = QLabel("Time: 00:00:00")
        self.lbl_down = QLabel("▼ 0 KB/s"); self.lbl_down.setStyleSheet("color: green; font-weight: bold;")
        self.lbl_up = QLabel("▲ 0 KB/s"); self.lbl_up.setStyleSheet("color: blue; font-weight: bold;")
        self.lbl_data = QLabel("Data: 0 B")

        v_left = QVBoxLayout()
        v_left.addWidget(self.lbl_time); v_left.addWidget(self.lbl_down)
        v_left.addWidget(self.lbl_up); v_left.addWidget(self.lbl_data); v_left.addStretch()

        self.info_container_right = QWidget()
        v_right = QVBoxLayout(self.info_container_right)
        v_right.setContentsMargins(0, 0, 0, 0)
        v_right.setSpacing(5)
        
        self.lbl_main_status = QLabel("🔴 CHƯA KẾT NỐI")
        self.lbl_main_status.setAlignment(Qt.AlignCenter)
        self.lbl_main_status.setStyleSheet("color: red; font-weight: bold; font-size: 12px;") 
        v_right.addWidget(self.lbl_main_status)

        self.stack_status_details = QStackedWidget()
        
        self.page_status_single = QWidget()
        l_status_single = QVBoxLayout(self.page_status_single)
        l_status_single.setContentsMargins(0,5,0,0)
        self.lbl_detail_host = QLabel("Host: -")
        row_loc = QHBoxLayout(); row_loc.setContentsMargins(0,0,0,0); row_loc.setSpacing(5)
        self.lbl_flag = QLabel()
        self.lbl_flag.setFixedSize(25, 18); self.lbl_flag.setScaledContents(True); self.lbl_flag.setVisible(False) 
        self.lbl_detail_loc = QLabel("Vị trí: -")
        row_loc.addWidget(self.lbl_flag); row_loc.addWidget(self.lbl_detail_loc); row_loc.addStretch()

        detail_style = "font-size: 14px; font-weight: 500;"
        self.lbl_detail_host.setStyleSheet(detail_style)
        self.lbl_detail_loc.setStyleSheet(detail_style)
        l_status_single.addWidget(self.lbl_detail_host); l_status_single.addLayout(row_loc); l_status_single.addStretch()
        
        self.page_status_multi = QWidget()
        l_status_multi = QVBoxLayout(self.page_status_multi)
        l_status_multi.setContentsMargins(0,5,0,0)
        self.lbl_multi_header = QLabel("Danh sách Server đang chạy:")
        self.lbl_multi_header.setStyleSheet("font-weight: bold; font-size: 12px; text-decoration: underline;")
        l_status_multi.addWidget(self.lbl_multi_header)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.NoFrame)
        self.container_ips = QWidget()
        self.layout_ips = QVBoxLayout(self.container_ips)
        self.layout_ips.setContentsMargins(0,0,0,0); self.layout_ips.setSpacing(2)
        scroll.setWidget(self.container_ips)
        l_status_multi.addWidget(scroll)
        
        self.stack_status_details.addWidget(self.page_status_single)
        self.stack_status_details.addWidget(self.page_status_multi)
        v_right.addWidget(self.stack_status_details)

        self.lbl_ping_jitter = QLabel("PING: N/A | JITTER: N/A")
        self.lbl_ping_jitter.setStyleSheet("color: #d63384; font-weight: bold; font-size: 11px;")
        self.lbl_ping_jitter.setAlignment(Qt.AlignRight)
        v_right.addWidget(self.lbl_ping_jitter)

        grid_net.addLayout(v_left, 0, 0)
        grid_net.addWidget(self.info_container_right, 0, 1)

        self.grp_net_status.setLayout(grid_net)
        layout.addWidget(self.grp_net_status)

        self.btn = QPushButton("KẾT NỐI"); self.btn.clicked.connect(self.start)
        self.btn.setStyleSheet("background: #28a745; color: white; padding: 10px; font-weight: bold")
        
        row_actions = QHBoxLayout()
        self.btn_stop = QPushButton("NGẮT KẾT NỐI"); self.btn_stop.clicked.connect(self.stop)
        self.btn_stop.setStyleSheet("background: #dc3545; color: white; padding: 10px; font-weight: bold")
        self.btn_stop.setEnabled(False)
        self.btn_quit = QPushButton("THOÁT"); self.btn_quit.clicked.connect(self.quit_app)
        self.btn_quit.setStyleSheet("background: #6c757d; color: white; padding: 10px; font-weight: bold")
        row_actions.addWidget(self.btn_stop); row_actions.addWidget(self.btn_quit)
        
        layout.addWidget(self.btn); layout.addLayout(row_actions)

        self.lbl_status = QLabel("Sẵn sàng")
        self.lbl_status.setAlignment(Qt.AlignCenter)
        self.update_status_label("Sẵn sàng")
        layout.addWidget(self.lbl_status)
        
        self.log_box = QTextEdit(); self.log_box.setReadOnly(True)
        self.log_box.setMaximumHeight(80) 
        layout.addWidget(self.log_box)

        self.tab_settings = QWidget() 
        self.tabs.addTab(self.tab_home, "🏠 Home ")
        self.tabs.addTab(self.tab_settings, "⚙️ Cài đặt")

    def initTray(self):
        self.tray_icon = QSystemTrayIcon(self)
        if os.path.exists("logo.ico"): self.tray_icon.setIcon(QIcon("logo.ico"))
        else: self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon)) 
        self.tray_icon.setToolTip("SSH Proxy: Disconnected") 
        self.update_tray_menu()
        self.tray_icon.activated.connect(self.on_tray_click)
        self.tray_icon.show()

    def update_tray_menu(self):
        menu = QMenu()
        if self.is_connected:
            action = QAction("⛔ Disconnected", self); action.triggered.connect(self.stop)
            menu.addAction(action)
        else:
            action = QAction("♻️ Connect", self); action.triggered.connect(self.start)
            menu.addAction(action)
        menu.addSeparator()
        action_show = QAction("🏠 Mở ứng dụng", self); action_show.triggered.connect(self.show_window)
        menu.addAction(action_show)
        action_quit = QAction("⚠️ Thoát hoàn toàn", self); action_quit.triggered.connect(self.quit_app)
        menu.addAction(action_quit)
        self.tray_icon.setContextMenu(menu)
        
    def update_tray_tooltip(self):
        if not self.is_connected:
            self.tray_icon.setToolTip("SSH Proxy: Disconnected")
            return
        
        # --- LOGIC MỚI: HIỂN THỊ IP SERVER ---
        server_info = ""
        if self.rad_single.isChecked():
            # Chế độ Single: Lấy IP từ danh sách đã kết nối thành công
            if self.connected_ips:
                server_info = f"Server: {self.connected_ips[0]}"
            else:
                # Nếu đang connecting chưa xong thì lấy text từ ô nhập
                current_host = self.host_box.currentText().strip()
                server_info = f"Connecting to: {current_host}..."
        else:
            # Chế độ Multi: Hiển thị số lượng server active
            count = len(self.connected_ips)
            if count == 0:
                server_info = "Load Balancer: Connecting..."
            else:
                server_info = f"Load Balancer: {count} Active Servers"
                # Nếu muốn hiện chi tiết vài IP đầu:
                # server_info += f"\n({', '.join(self.connected_ips[:2])}...)"
        # -------------------------------------

        # Ghép chuỗi hiển thị
        tip = f"{server_info}"
        
        if self.chk_show_info.isChecked():
            tip += f"\nPing: {self.last_ping} | Jitter: {self.last_jitter}"
        else:
            tip += "\nNet Info: Hidden"
            
        self.tray_icon.setToolTip(tip)

    def toggle_mode_ui(self):
        if self.rad_single.isChecked():
            self.stack_ui.setCurrentIndex(0)
            self.stack_status_details.setCurrentIndex(0) 
            self.setWindowTitle("SSH Proxy Optimized - Single")
        else:
            self.stack_ui.setCurrentIndex(1)
            self.stack_status_details.setCurrentIndex(1) 
            self.setWindowTitle("SSH Proxy Optimized - Balancer")
            self.refresh_multi_table()

    def toggle_select_all(self):
        is_selecting = "Check all" in self.btn_select_all.text()
        new_state = True if is_selecting else False
        for i in range(self.table_multi.rowCount()):
            w1 = self.table_multi.cellWidget(i, 0)
            if w1:
                chk = w1.findChild(QCheckBox)
                if chk: chk.setChecked(new_state)
            w2 = self.table_multi.cellWidget(i, 2)
            if w2:
                chk = w2.findChild(QCheckBox)
                if chk: chk.setChecked(new_state)
        if is_selecting: self.btn_select_all.setText("☐ uncheck ")
        else: self.btn_select_all.setText("☑️ Check all ")

    def toggle_info_display(self):
        show = self.chk_show_info.isChecked()
        self.grp_net_status.setVisible(True) 
        self.info_container_right.setVisible(show) 
        if not show:
            if self.checker_thread and self.checker_thread.isRunning(): self.checker_thread.quit()
            if self.geoip_worker and self.geoip_worker.isRunning(): self.geoip_worker.quit()
        elif show and self.is_connected:
             self.trigger_ping_check()
             if self.rad_single.isChecked() and self.connected_ips: self.update_connected_ips_ui(self.connected_ips)

    def update_status_label(self, text):
        style = "font-weight: bold; font-size: 14px; padding: 5px;"
        text_lower = text.lower()
        if "sẵn sàng" in text_lower: style += " color: #007bff;"
        elif "connecting" in text_lower or "engine" in text_lower: style += " color: #ffc107;"
        elif "running" in text_lower or "ready" in text_lower: style += " color: #28a745;"
        else: style += " color: #dc3545;"
        self.lbl_status.setText(text)
        self.lbl_status.setStyleSheet(style)

    def open_history_manager(self):
        manager = HistoryManager(self.history_data, self)
        manager.exec_()
        self.refresh_combo_box()
        self.refresh_multi_table()
        self.save_config()

    def on_host_selected(self, index):
        if index < 0 or index >= len(self.history_data): return
        item = self.history_data[index]
        self.user_box.setText(item.get("user", ""))
        self.pwd.setText(item.get("pass", ""))
        
    def add_to_history(self, h, u, p, ssh_port=22):
        if not h: return
        exists = False
        for item in self.history_data:
            if item["host"] == h:
                item["user"] = u; item["pass"] = p
                item["ssh_port"] = ssh_port
                exists = True; break
        if not exists: self.history_data.insert(0, {"host": h, "user": u, "pass": p, "ssh_port": ssh_port})
        self.refresh_combo_box()
        self.refresh_multi_table()

    def refresh_combo_box(self):
        current = self.host_box.currentText()
        self.host_box.blockSignals(True)
        self.host_box.clear()
        for item in self.history_data: self.host_box.addItem(item['host'])
        self.host_box.setEditText(current)
        self.host_box.blockSignals(False)

    def refresh_multi_table(self):
        checked_hosts = set()
        for i in range(self.table_multi.rowCount()):
            w1 = self.table_multi.cellWidget(i, 0)
            if w1:
                chk = w1.findChild(QCheckBox)
                if chk and chk.isChecked():
                    h1 = self.table_multi.item(i, 1).text(); checked_hosts.add(h1)
            w2 = self.table_multi.cellWidget(i, 2)
            if w2:
                chk = w2.findChild(QCheckBox)
                if chk and chk.isChecked():
                    h2 = self.table_multi.item(i, 3).text(); checked_hosts.add(h2)

        self.table_multi.setRowCount(0)
        count = len(self.history_data)
        rows_needed = (count + 1) // 2
        self.table_multi.setRowCount(rows_needed)
        
        for i in range(rows_needed):
            idx1 = i * 2
            if idx1 < count:
                item1 = self.history_data[idx1]
                host1 = item1.get('host', '')
                chk_box = QCheckBox()
                if host1 in checked_hosts: chk_box.setChecked(True)
                w = QWidget(); l = QHBoxLayout(w); l.addWidget(chk_box); l.setAlignment(Qt.AlignCenter); l.setContentsMargins(0,0,0,0)
                self.table_multi.setCellWidget(i, 0, w)
                self.table_multi.setItem(i, 1, QTableWidgetItem(host1))
            idx2 = i * 2 + 1
            if idx2 < count:
                item2 = self.history_data[idx2]
                host2 = item2.get('host', '')
                chk_box = QCheckBox()
                if host2 in checked_hosts: chk_box.setChecked(True)
                w = QWidget(); l = QHBoxLayout(w); l.addWidget(chk_box); l.setAlignment(Qt.AlignCenter); l.setContentsMargins(0,0,0,0)
                self.table_multi.setCellWidget(i, 2, w)
                self.table_multi.setItem(i, 3, QTableWidgetItem(host2))
        self.btn_select_all.setText("☑️ Check all")

    def trigger_ping_check(self):
        if not self.chk_show_info.isChecked(): return
        if not self.is_connected: return
        port_txt = self.port.text().strip()
        if not port_txt: return
        if self.checker_thread and self.checker_thread.isRunning(): return 
        self.checker_thread = NetworkChecker(port_txt)
        self.checker_thread.info_signal.connect(self.update_ping_ui)
        self.checker_thread.start()

    def update_ping_ui(self, info):
        if not self.chk_show_info.isChecked(): return
        self.last_ping = info.get("ping", "N/A")
        self.last_jitter = info.get("jitter", "N/A")
        self.lbl_ping_jitter.setText(f"PING: {self.last_ping} | JITTER: {self.last_jitter}")
        self.update_tray_tooltip()

    def update_connected_ips_ui(self, ip_list):
        self.connected_ips = ip_list
        is_multi = self.rad_multi.isChecked()
        
        if ip_list:
            self.lbl_main_status.setText("🟢 KẾT NỐI THÀNH CÔNG")
            self.lbl_main_status.setStyleSheet("color: green; font-weight: bold; font-size: 12px;")
        else:
            pass 

        if not is_multi:
            if len(ip_list) == 1 and self.chk_show_info.isChecked():
                host = ip_list[0]
                if self.lbl_detail_host.text() != f"Host: {host}":
                    self.lbl_detail_host.setText(f"Host: {host}")
                    if self.geoip_worker and self.geoip_worker.isRunning():
                        self.geoip_worker.terminate()
                    self.lbl_detail_loc.setText("Vị trí: Đang tải...")
                    self.lbl_flag.setVisible(False)
                    
                    self.geoip_worker = GeoIPWorker(host, self.geoip_priority)
                    self.geoip_worker.info_signal.connect(self.update_geoip_ui)
                    self.geoip_worker.start()
        else:
            while self.layout_ips.count():
                item = self.layout_ips.takeAt(0)
                if item.widget(): item.widget().deleteLater()
            
            for ip in ip_list:
                lbl = QLabel(f"🟢 {ip}")
                lbl.setStyleSheet("color: #333; font-size: 11px;")
                self.layout_ips.addWidget(lbl)
            self.layout_ips.addStretch()
            
        # --- THÊM DÒNG NÀY ĐỂ CẬP NHẬT TOOLTIP TRAY NGAY LẬP TỨC ---
        self.update_tray_tooltip() 
        # -----------------------------------------------------------

    def update_geoip_ui(self, data):
        if not self.chk_show_info.isChecked(): return
        if data.get('status') == 'success':
            country = data.get('country', 'Unknown')
            city = data.get('city', 'Unknown')
            country_code = data.get('countryCode', '').lower()
            self.lbl_detail_loc.setText(f"{city}, {country}")
            if country_code:
                flag_path = resource_path(f"flag/{country_code}.svg")
                if os.path.exists(flag_path):
                    self.lbl_flag.setPixmap(QPixmap(flag_path))
                    self.lbl_flag.setVisible(True)
                else: self.lbl_flag.setVisible(False)
            else: self.lbl_flag.setVisible(False)
        else:
            self.lbl_detail_loc.setText("Vị trí: Không tìm thấy")
            self.lbl_flag.setVisible(False)

    def start(self):
        if self.is_connected:
            self.append_log(">> 🔄 Restarting engine...")
            self.stop()
        
        self.log_box.clear()
        main_port = self.port.text().strip()
        if not main_port: main_port = "10800"

        if self.chk_random_port.isChecked():
            main_port = str(random.randint(10000, 60000))
            self.port.setText(main_port)
            self.append_log(f">> Random Port Selected: {main_port}")

        targets = []
        if self.rad_single.isChecked():
            h = self.host_box.currentText().strip()
            u = self.user_box.text().strip()
            p = self.pwd.text().strip()
            ssh_p = 22
            if self.chk_custom_ssh_port.isChecked():
                try: ssh_p = int(self.txt_ssh_port.text().strip())
                except: ssh_p = 22
            if not h: return self.lbl_status.setText("Thiếu Host IP!")
            if self.chk_save.isChecked(): self.add_to_history(h, u, p, ssh_p)
            targets.append({"host": h, "user": u, "pass": p, "ssh_port": ssh_p})
            self.lbl_detail_host.setText("Host: Connecting...")
            self.lbl_detail_loc.setText("Vị trí: -")
            self.lbl_flag.setVisible(False)
            self.stack_status_details.setCurrentIndex(0)
        else:
            for i in range(self.table_multi.rowCount()):
                w1 = self.table_multi.cellWidget(i, 0)
                if w1:
                    chk = w1.findChild(QCheckBox)
                    if chk and chk.isChecked():
                        h1 = self.table_multi.item(i, 1).text()
                        for item in self.history_data:
                            if item['host'] == h1: targets.append(item); break
                w2 = self.table_multi.cellWidget(i, 2)
                if w2:
                    chk = w2.findChild(QCheckBox)
                    if chk and chk.isChecked():
                        if self.table_multi.item(i, 3): 
                            h2 = self.table_multi.item(i, 3).text()
                            for item in self.history_data:
                                if item['host'] == h2: targets.append(item); break
            if not targets:
                QMessageBox.warning(self, "Lỗi", "Vui lòng chọn ít nhất 1 server!")
                return
            self.stack_status_details.setCurrentIndex(1)

        self.save_config()
        self.update_status_label("⏳ Starting Engine...")
        self.lbl_main_status.setText("🟡 ĐANG KẾT NỐI...")
        self.lbl_main_status.setStyleSheet("color: #d39e00; font-weight: bold; font-size: 12px;")
        self.btn.setEnabled(True); self.btn_stop.setEnabled(True)

        buf_str = self.cmb_buffer.currentText().replace("KB", "")
        try: buf_size = int(buf_str) * 1024
        except: buf_size = 65536

        self.network_engine = NetworkEngine(main_port, targets, buffer_size=buf_size)
        self.network_engine.log_signal.connect(self.append_log)
        self.network_engine.status_signal.connect(self.update_status_label)
        self.network_engine.active_hosts_signal.connect(self.update_connected_ips_ui)
        self.network_engine.start()

        if self.chk_sys.isChecked():
            SystemProxyManager.set_proxy("127.0.0.1", main_port)
            self.append_log(f">> System Proxy: ON (127.0.0.1:{main_port})")

        self.is_connected = True
        self.update_tray_tooltip()
        self.update_tray_menu()
        self.start_time = time.time()
        self.initial_net_io = psutil.net_io_counters(); self.last_net_io = self.initial_net_io
        self.monitor_timer.start(1000)
        
        if self.chk_show_info.isChecked():
            QTimer.singleShot(2000, self.trigger_ping_check)
            self.ping_check_timer.start()

    def stop(self):
        self.monitor_timer.stop() 
        self.ping_check_timer.stop()
        if self.checker_thread: self.checker_thread.terminate()
        if self.geoip_worker: self.geoip_worker.terminate()
        self.update_status_label("⛔ Disconnected")
        self.lbl_main_status.setText("🔴 CHƯA KẾT NỐI")
        self.lbl_main_status.setStyleSheet("color: red; font-weight: bold; font-size: 12px;")
        self.btn.setEnabled(True); self.btn_stop.setEnabled(False)
        self.is_connected = False
        self.update_tray_tooltip()
        self.update_tray_menu()
        self.lbl_down.setText("▼ 0 KB/s"); self.lbl_up.setText("▲ 0 KB/s")
        while self.layout_ips.count():
            item = self.layout_ips.takeAt(0)
            if item.widget(): item.widget().deleteLater()
        self.lbl_detail_host.setText("Host: -"); self.lbl_detail_loc.setText("Vị trí: -")
        self.lbl_flag.setVisible(False); self.lbl_ping_jitter.setText("PING: N/A | JITTER: N/A")
        self.last_ping = "N/A"; self.last_jitter = "N/A"
        if self.network_engine:
            self.network_engine.stop()
            self.network_engine = None
        SystemProxyManager.disable_proxy()
        self.append_log(">> Stopped all services.")

    def update_stats(self):
        elapsed = int(time.time() - self.start_time)
        time_str = time.strftime('%H:%M:%S', time.gmtime(elapsed))
        self.lbl_time.setText(f"Time: {time_str}")
        try:
            current_net = psutil.net_io_counters()
            if self.last_net_io:
                d = current_net.bytes_recv - self.last_net_io.bytes_recv
                u = current_net.bytes_sent - self.last_net_io.bytes_sent
                t = (current_net.bytes_recv - self.initial_net_io.bytes_recv) + \
                    (current_net.bytes_sent - self.initial_net_io.bytes_sent)
                self.lbl_down.setText(f"▼ {format_speed(d)}")
                self.lbl_up.setText(f"▲ {format_speed(u)}")
                self.lbl_data.setText(f"Data: {format_size(t)}")
            self.last_net_io = current_net
        except: pass

    def append_log(self, text):
        self.log_box.append(text); self.log_box.moveCursor(QTextCursor.End)

    def apply_settings_style(self, conf):
        font_family = conf.get("font_family", "Segoe UI")
        font_size = conf.get("font_size", 9)
        app_font = QFont(font_family, font_size)
        QApplication.setFont(app_font)
        bg_color = conf.get("bg_color", "#f0f0f0")
        text_color = conf.get("text_color", "#000000")
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{ background-color: {bg_color}; color: {text_color}; }}
            QGroupBox {{ border: 1px solid #aaa; margin-top: 10px; }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 3px; }}
            QLineEdit, QTextEdit, QTableWidget {{ background-color: white; color: black; border: 1px solid #ccc; }}
            QTabBar::tab {{ background: #e1e1e1; color: black; padding: 8px; }}
            QTabBar::tab:selected {{ background: white; font-weight: bold; }}
        """)
        self.geoip_priority = conf.get("geoip_priority", [])

    def on_settings_save(self, new_conf):
        self.apply_settings_style(new_conf)
        self.settings.setValue("font_family", new_conf["font_family"])
        self.settings.setValue("font_size", new_conf["font_size"])
        self.settings.setValue("bg_color", new_conf["bg_color"])
        self.settings.setValue("text_color", new_conf["text_color"])
        self.settings.setValue("geoip_priority", new_conf["geoip_priority"])
        QMessageBox.information(self, "Thành công", "Đã lưu cài đặt!")

    def save_config(self):
        self.settings.setValue("port_socks", self.port.text())
        self.settings.setValue("chk_sys", str(self.chk_sys.isChecked()))
        self.settings.setValue("chk_tray", str(self.chk_tray.isChecked()))
        self.settings.setValue("chk_save", str(self.chk_save.isChecked()))
        self.settings.setValue("chk_random", str(self.chk_random_port.isChecked()))
        self.settings.setValue("mode_multi", str(self.rad_multi.isChecked()))
        self.settings.setValue("buffer_idx", self.cmb_buffer.currentIndex())
        self.settings.setValue("chk_custom_ssh_port", str(self.chk_custom_ssh_port.isChecked()))
        self.settings.setValue("txt_ssh_port", self.txt_ssh_port.text())
        self.settings.setValue("chk_show_info", str(self.chk_show_info.isChecked()))
        if self.chk_save.isChecked(): 
            json_str = json.dumps(self.history_data)
            self.settings.setValue("history_data", encrypt_text(json_str))
            self.settings.setValue("last_host", self.host_box.currentText())

    def load_config(self):
        widgets = [self.chk_sys, self.chk_tray, self.chk_save, self.chk_random_port, 
                   self.port, self.cmb_buffer, self.chk_custom_ssh_port, self.txt_ssh_port, self.chk_show_info]
        for w in widgets: w.blockSignals(True)
        self.port.setText(self.settings.value("port_socks", "10800"))
        self.chk_sys.setChecked(str2bool(self.settings.value("chk_sys", "true")))
        self.chk_tray.setChecked(str2bool(self.settings.value("chk_tray", "true")))
        self.chk_save.setChecked(str2bool(self.settings.value("chk_save", "true")))
        self.chk_random_port.setChecked(str2bool(self.settings.value("chk_random", "false")))
        self.cmb_buffer.setCurrentIndex(int(self.settings.value("buffer_idx", 1))) 
        self.chk_custom_ssh_port.setChecked(str2bool(self.settings.value("chk_custom_ssh_port", "false")))
        self.txt_ssh_port.setText(self.settings.value("txt_ssh_port", "22"))
        self.txt_ssh_port.setEnabled(self.chk_custom_ssh_port.isChecked())
        self.chk_show_info.setChecked(str2bool(self.settings.value("chk_show_info", "true")))
        self.toggle_info_display()

        is_multi = str2bool(self.settings.value("mode_multi", "false"))
        if is_multi: self.rad_multi.setChecked(True)
        else: self.rad_single.setChecked(True)

        try:
            raw_data = self.settings.value("history_data", "")
            if raw_data:
                # Thử giải mã mới
                try: self.history_data = json.loads(decrypt_text(raw_data))
                except:
                    # Fallback cho data cũ (base64 simple)
                    try:
                        b64_rev = base64.b64decode(raw_data.encode()).decode()
                        rev = b64_rev[::-1]
                        self.history_data = json.loads(base64.b64decode(rev.encode()).decode())
                    except: self.history_data = []
            else: self.history_data = []
        except: self.history_data = []
        
        self.refresh_combo_box()
        self.refresh_multi_table()
        last_h = self.settings.value("last_host", "")
        if last_h:
            idx = self.host_box.findText(last_h)
            if idx >= 0: self.host_box.setCurrentIndex(idx); self.on_host_selected(idx)
        for w in widgets: w.blockSignals(False)
        self.toggle_mode_ui()

        conf = {
            "font_family": self.settings.value("font_family", "Segoe UI"),
            "font_size": int(self.settings.value("font_size", 9)),
            "bg_color": self.settings.value("bg_color", "#f0f0f0"),
            "text_color": self.settings.value("text_color", "#000000"),
            "geoip_priority": self.settings.value("geoip_priority", [])
        }
        self.settings_tab_ui = SettingsTab(conf)
        self.settings_tab_ui.settings_saved.connect(self.on_settings_save)
        l = QVBoxLayout(self.tab_settings)
        l.addWidget(self.settings_tab_ui)
        self.apply_settings_style(conf)

    def closeEvent(self, event):
        if self.chk_tray.isChecked():
            event.ignore(); self.hide()
            self.tray_icon.showMessage("Running", "Ứng dụng đang chạy ngầm...", QSystemTrayIcon.Information, 1000)
        else: event.ignore(); self.quit_app()

    def show_window(self):
        self.show(); self.setWindowState(Qt.WindowNoState); self.activateWindow()

    def on_tray_click(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            if self.isVisible(): self.hide()
            else: self.show_window()

    def quit_app(self):
        self.hide()
        # Clean shutdown
        SystemProxyManager.disable_proxy()
        try: self.tray_icon.hide()
        except: pass
        if self.network_engine: self.network_engine.stop()
        os._exit(0)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion") 
    myappid = 'vn.sshproxy.async.secure' 
    try: ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    except: pass
    win = SSHProxyApp(); win.show()
    sys.exit(app.exec_())