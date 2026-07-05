import os
import json
import re
import shutil
import socket
import hashlib
import subprocess
import threading
import time
import sys
import platform
from datetime import datetime, timedelta

import psutil
from flask import Flask, send_from_directory, request, jsonify, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

USERS_ROOT = os.path.join(BASE_DIR, "USERS")
DATA_DIR = os.path.join(BASE_DIR, "DATA")
USERS_DB = os.path.join(DATA_DIR, "users.json")

os.makedirs(USERS_ROOT, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("PANEL_SECRET_KEY", "MOUHAMED_HOST_MA" + os.urandom(16).hex())

# ===== Admin credentials =====
ADMIN_USERNAME = os.environ.get("ADMIN_USER", "MOUHANED23")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "MOUHAMED04")

running_procs = {}
server_states = {}
lock = threading.Lock()


def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def sanitize_folder_name(name: str) -> str:
    name = (name or "").strip()
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"[^A-Za-z0-9\-_\.]", "", name)
    return name[:200]


def safe_name(name: str) -> str:
    name = (name or "").strip()
    name = re.sub(r"[\\/]+", "", name)
    name = re.sub(r"[^A-Za-z0-9\-_\. ]", "", name)
    return name[:200].strip()


def set_state(key: str, state: str):
    with lock:
        server_states[key] = state


def get_state(key: str) -> str:
    with lock:
        return server_states.get(key, "Offline")


def log_append(key: str, text: str):
    try:
        owner, folder = parse_server_key(key, allow_admin=True)
        p = os.path.join(get_server_dir(owner, folder), "server.log")
        with open(p, "a", encoding="utf-8", errors="ignore") as f:
            f.write(text)
    except Exception:
        pass


# ---------------------------
# Users DB
# ---------------------------
def load_users():
    if not os.path.exists(USERS_DB):
        return {"users": []}
    try:
        with open(USERS_DB, "r", encoding="utf-8") as f:
            return json.load(f) or {"users": []}
    except Exception:
        return {"users": []}


def save_users(db):
    tmp = USERS_DB + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)
    os.replace(tmp, USERS_DB)


def find_user(db, username: str):
    u = (username or "").strip().lower()
    for x in db.get("users", []):
        if (x.get("username") or "").strip().lower() == u:
            return x
    return None


def is_admin_session():
    u = session.get("user") or {}
    return bool(u.get("is_admin"))


def current_username():
    u = session.get("user") or {}
    return (u.get("username") or "").strip()


def get_user_server_limit(username: str) -> int:
    if is_admin_session():
        return 999999
    db = load_users()
    u = find_user(db, username)
    if not u:
        return 1
    # Use custom server_limit if set, otherwise premium=5, normal=1
    return u.get("server_limit", 5 if u.get("premium", False) else 1)


def is_user_expired(u: dict) -> bool:
    """Check if user subscription has expired"""
    expiry = u.get("expiry")
    if not expiry:
        return False
    try:
        exp_date = datetime.fromisoformat(expiry)
        return datetime.now() > exp_date
    except Exception:
        return False


# ---------------------------
# Auth decorators
# ---------------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/login")
        if not is_admin_session():
            return jsonify({"success": False, "message": "Admin only"}), 403
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------
# Per-user server directories
# ---------------------------
def get_user_servers_root(username: str) -> str:
    return os.path.join(USERS_ROOT, username, "servers")


def get_server_dir(owner: str, folder: str) -> str:
    return os.path.join(get_user_servers_root(owner), folder)


def ensure_user_dirs(username: str):
    os.makedirs(get_user_servers_root(username), exist_ok=True)


def parse_server_key(key: str, allow_admin: bool):
    key = (key or "").strip()
    if "::" in key:
        owner, folder = key.split("::", 1)
        owner = owner.strip()
        folder = folder.strip()
        if not allow_admin:
            raise ValueError("not allowed")
        if not is_admin_session():
            raise ValueError("forbidden")
        return owner, folder
    return current_username(), key


def can_access_key(key: str) -> bool:
    try:
        owner, folder = parse_server_key(key, allow_admin=True)
    except Exception:
        return False
    if is_admin_session():
        return True
    return owner == current_username()


def safe_join_server_path(key: str, rel_path: str = "") -> str:
    owner, folder = parse_server_key(key, allow_admin=True)
    root = os.path.abspath(get_server_dir(owner, folder))
    rel_path = (rel_path or "").replace("\\", "/").strip()
    if rel_path.startswith("/") or rel_path.startswith("~"):
        rel_path = rel_path.lstrip("/").lstrip("~")
    joined = os.path.abspath(os.path.join(root, rel_path))
    if not (joined == root or joined.startswith(root + os.sep)):
        raise ValueError("Invalid path")
    return joined


# ---------------------------
# Meta per server
# ---------------------------
def ensure_meta(owner: str, folder: str):
    server_dir = get_server_dir(owner, folder)
    os.makedirs(server_dir, exist_ok=True)
    meta_path = os.path.join(server_dir, "meta.json")
    base = {"display_name": folder, "startup_file": "", "owner": owner, "banned": False}
    if not os.path.exists(meta_path):
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(base, f, indent=2)
    else:
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                m = json.load(f) or {}
        except Exception:
            m = {}
        changed = False
        for k, v in base.items():
            if k not in m:
                m[k] = v
                changed = True
        if m.get("owner") != owner:
            m["owner"] = owner
            changed = True
        if changed:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(m, f, indent=2)
    return meta_path


def read_meta(owner: str, folder: str):
    meta_path = ensure_meta(owner, folder)
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {"display_name": folder, "startup_file": "", "owner": owner, "banned": False}


def write_meta(owner: str, folder: str, meta):
    meta_path = ensure_meta(owner, folder)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


# ---------------------------
# Auto-install system
# ---------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def installed_file_path(owner: str, folder: str):
    return os.path.join(get_server_dir(owner, folder), ".installed")


def read_installed(owner: str, folder: str):
    p = installed_file_path(owner, folder)
    data = {"req_sha": "", "pkgs": set()}
    if not os.path.exists(p):
        return data
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f.read().splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("REQ_SHA="):
                    data["req_sha"] = line.split("=", 1)[1].strip()
                else:
                    data["pkgs"].add(line)
    except Exception:
        pass
    return data


def write_installed(owner: str, folder: str, req_sha=None, add_pkgs=None):
    p = installed_file_path(owner, folder)
    cur = read_installed(owner, folder)
    if req_sha is not None:
        cur["req_sha"] = req_sha
    if add_pkgs:
        cur["pkgs"].update(add_pkgs)
    lines = []
    if cur["req_sha"]:
        lines.append(f"REQ_SHA={cur['req_sha']}")
    lines.extend(sorted(cur["pkgs"]))
    with open(p, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def ensure_requirements_installed(owner: str, folder: str):
    server_dir = get_server_dir(owner, folder)
    req_path = os.path.join(server_dir, "requirements.txt")
    if not os.path.exists(req_path):
        return False

    req_sha = sha256_file(req_path)
    cur = read_installed(owner, folder)
    if cur["req_sha"] == req_sha:
        return False

    log_append(f"{owner}::{folder}", "\n" + "="*60 + "\n")
    log_append(f"{owner}::{folder}", "[SYSTEM] جاري تثبيت المكاتب المطلوبة...\n")
    log_append(f"{owner}::{folder}", "="*60 + "\n")
    try:
        result = subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                              cwd=server_dir, capture_output=True, text=True)
        if result.stdout:
            log_append(f"{owner}::{folder}", result.stdout)
        if result.stderr:
            log_append(f"{owner}::{folder}", result.stderr)
        write_installed(owner, folder, req_sha=req_sha)
        log_append(f"{owner}::{folder}", "\n" + "="*60 + "\n")
        log_append(f"{owner}::{folder}", "[SYSTEM] ✅ تم تثبيت جميع المكاتب بنجاح!\n")
        log_append(f"{owner}::{folder}", "="*60 + "\n\n")
        return True
    except Exception as e:
        log_append(f"{owner}::{folder}", f"[SYSTEM] ❌ فشل التثبيت: {e}\n")
        return False


def start_with_autoinstall(owner: str, folder: str, startup_file: str):
    wrapper_code = r'''
import runpy, sys, subprocess, traceback, re, os
script = sys.argv[1]
cwd = os.getcwd()

def append_installed(pkg):
    try:
        p = os.path.join(cwd, ".installed")
        existing = set()
        if os.path.exists(p):
            with open(p) as f:
                existing = set(l.strip() for l in f if l.strip() and not l.startswith("REQ_SHA="))
        existing.add(pkg)
        with open(p, "a") as f:
            f.write(pkg + "\n")
    except Exception:
        pass

_real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

import builtins
_orig = builtins.__import__

def _patched_import(name, *args, **kwargs):
    try:
        return _orig(name, *args, **kwargs)
    except ImportError:
        pkg = name.split(".")[0].replace("_", "-")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            append_installed(pkg)
            return _orig(name, *args, **kwargs)
        except Exception:
            raise ImportError(name)

builtins.__import__ = _patched_import

try:
    runpy.run_path(script, run_name="__main__")
except SystemExit:
    pass
except Exception:
    traceback.print_exc()
'''
    wrapper_path = os.path.join(get_server_dir(owner, folder), "_runner.py")
    with open(wrapper_path, "w", encoding="utf-8") as f:
        f.write(wrapper_code)

    server_dir = get_server_dir(owner, folder)
    log_path = os.path.join(server_dir, "server.log")
    logf = open(log_path, "a", encoding="utf-8", errors="ignore")
    
    # Add startup message
    logf.write("\n" + "="*60 + "\n")
    logf.write(f"[SYSTEM] بدء تشغيل البوت - {startup_file}\n")
    logf.write("="*60 + "\n\n")
    logf.flush()

    proc = subprocess.Popen(
        [sys.executable, wrapper_path, startup_file],
        cwd=server_dir,
        stdout=logf,
        stderr=logf,
        text=True,
        bufsize=1
    )
    return proc, logf


def stop_proc(key: str):
    proc_tuple = running_procs.get(key)
    if not proc_tuple:
        return
    proc, logf = proc_tuple
    try:
        p = psutil.Process(proc.pid)
        for child in p.children(recursive=True):
            child.kill()
        p.kill()
    except Exception:
        pass
    try:
        logf.close()
    except Exception:
        pass
    running_procs.pop(key, None)


# ---------------------------
# Pages
# ---------------------------
@app.route("/")
@login_required
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/login")
def login_page():
    return send_from_directory(BASE_DIR, "login.html")


@app.route("/create")
def create_page():
    # Redirect to login - account creation is admin-only now
    return redirect("/login")


@app.route("/admin")
@login_required
def admin_page():
    if not is_admin_session():
        return redirect("/")
    return send_from_directory(BASE_DIR, "admin.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


# ---------------------------
# Auth APIs
# ---------------------------
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session["user"] = {"username": ADMIN_USERNAME, "is_admin": True}
        return jsonify({"success": True, "is_admin": True})

    db = load_users()
    u = find_user(db, username)
    if not u:
        return jsonify({"success": False, "message": "اسم المستخدم أو كلمة المرور غير صحيحة"}), 401
    if not u.get("active", True):
        return jsonify({"success": False, "message": "الحساب محظور. تواصل مع المسؤول"}), 403

    # Check expiry
    if is_user_expired(u):
        return jsonify({"success": False, "message": "انتهت صلاحية الاشتراك. تواصل مع المسؤول"}), 403

    if not check_password_hash(u.get("password_hash", ""), password):
        return jsonify({"success": False, "message": "اسم المستخدم أو كلمة المرور غير صحيحة"}), 401

    session["user"] = {"username": u.get("username"), "is_admin": False}
    ensure_user_dirs(u.get("username"))
    return jsonify({"success": True, "is_admin": False})


# Disable public account creation - admin only
@app.route("/api/auth/create", methods=["POST"])
def api_create():
    return jsonify({"success": False, "message": "إنشاء الحسابات متاح للمسؤول فقط"}), 403


# ---------------------------
# Server listing
# ---------------------------
def list_all_servers_for_admin():
    servers = []
    if not os.path.isdir(USERS_ROOT):
        return servers

    for owner in sorted(os.listdir(USERS_ROOT)):
        root = get_user_servers_root(owner)
        if not os.path.isdir(root):
            continue
        for folder in sorted(os.listdir(root)):
            server_dir = get_server_dir(owner, folder)
            if not os.path.isdir(server_dir):
                continue
            meta = read_meta(owner, folder)
            banned = bool(meta.get("banned", False))
            key = f"{owner}::{folder}"
            st = "Banned" if banned else get_state(key)
            servers.append({
                "title": meta.get("display_name", folder),
                "folder": folder,
                "owner": owner,
                "key": key,
                "subtitle": f"المالك: {owner}",
                "startup_file": meta.get("startup_file", ""),
                "status": st
            })
    return servers


def list_servers_for_user(username: str):
    ensure_user_dirs(username)
    root = get_user_servers_root(username)
    servers = []
    for folder in sorted(os.listdir(root)):
        server_dir = get_server_dir(username, folder)
        if not os.path.isdir(server_dir):
            continue
        meta = read_meta(username, folder)
        banned = bool(meta.get("banned", False))
        key = folder
        st = "Banned" if banned else get_state(key)
        servers.append({
            "title": meta.get("display_name", folder),
            "folder": folder,
            "owner": username,
            "key": key,
            "subtitle": f"المالك: {username}",
            "startup_file": meta.get("startup_file", ""),
            "status": st
        })
    return servers


@app.route("/servers")
@login_required
def servers():
    if is_admin_session():
        return jsonify({"success": True, "servers": list_all_servers_for_admin()})
    return jsonify({"success": True, "servers": list_servers_for_user(current_username())})


@app.route("/add", methods=["POST"])
@login_required
def add_server():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    folder = sanitize_folder_name(name)
    if not folder:
        return jsonify({"success": False, "message": "اسم السيرفر غير صالح"}), 400

    owner = current_username()
    ensure_user_dirs(owner)

    if not is_admin_session():
        limit = get_user_server_limit(owner)
        existing = [d for d in os.listdir(get_user_servers_root(owner)) if os.path.isdir(get_server_dir(owner, d))]
        if len(existing) >= limit:
            return jsonify({"success": False, "message": f"وصلت للحد الأقصى ({limit} سيرفر). تواصل مع المسؤول"}), 403

    target = get_server_dir(owner, folder)
    if os.path.exists(target):
        return jsonify({"success": False, "message": "السيرفر موجود مسبقاً"}), 409

    os.makedirs(target, exist_ok=True)
    open(os.path.join(target, "server.log"), "w", encoding="utf-8").close()

    meta = {
        "display_name": name or folder,
        "startup_file": "",
        "owner": owner,
        "banned": False
    }
    write_meta(owner, folder, meta)
    set_state(folder if not is_admin_session() else f"{owner}::{folder}", "Offline")

    if is_admin_session():
        return jsonify({"success": True, "servers": list_all_servers_for_admin()})
    return jsonify({"success": True, "servers": list_servers_for_user(owner)})


# ---------------------------
# Server control + stats
# ---------------------------
@app.route("/server/stats/<path:key>")
@login_required
def server_stats(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"status": "Offline", "cpu": "0%", "mem": "0 MB", "logs": "", "ip": get_ip()}), 404

    meta = read_meta(owner, folder)
    if meta.get("banned", False):
        set_state(key, "Banned")

    proc_tuple = running_procs.get(key)
    running = False
    cpu, mem = "0%", "0 MB"

    if proc_tuple:
        proc, _logf = proc_tuple
        if psutil.pid_exists(proc.pid):
            try:
                p = psutil.Process(proc.pid)
                if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                    running = True
                    cpu = f"{p.cpu_percent(interval=None)}%"
                    mem = f"{p.memory_info().rss / 1024 / 1024:.1f} MB"
            except Exception:
                pass

    log_path = os.path.join(server_dir, "server.log")
    try:
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                all_logs = f.read()
                lines = all_logs.split('\n')
                last_15_lines = lines[-15:]
                logs = '\n'.join(last_15_lines)
        else:
            logs = ""
    except Exception:
        logs = ""

    state = get_state(key)
    if meta.get("banned", False):
        state = "Banned"
    elif running:
        state = "Running"
        set_state(key, "Running")
    elif state not in ("Installing", "Starting"):
        state = "Offline"
        set_state(key, "Offline")

    return jsonify({"status": state, "cpu": cpu, "mem": mem, "logs": logs, "ip": get_ip()})


def background_start(key: str, owner: str, folder: str, startup_file: str):
    try:
        set_state(key, "Installing")
        log_append(key, "[SYSTEM] جاري التحضير...\n")

        ensure_requirements_installed(owner, folder)

        set_state(key, "Starting")
        log_append(key, "[SYSTEM] جاري التشغيل...\n")

        proc, logf = start_with_autoinstall(owner, folder, startup_file)
        running_procs[key] = (proc, logf)

        time.sleep(1.0)
        if proc.poll() is None:
            set_state(key, "Running")
        else:
            set_state(key, "Offline")
    except Exception as e:
        log_append(key, f"[SYSTEM] فشل التشغيل: {e}\n")
        set_state(key, "Offline")


@app.route("/server/action/<path:key>/<act>", methods=["POST"])
@login_required
def server_action(key, act):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "السيرفر غير موجود"}), 404

    meta = read_meta(owner, folder)
    if meta.get("banned", False):
        set_state(key, "Banned")
        return jsonify({"success": False, "message": "السيرفر محظور من قبل المسؤول"}), 403

    if act in ("stop", "restart"):
        stop_proc(key)
        set_state(key, "Offline")

    if act == "stop":
        return jsonify({"success": True})

    startup = meta.get("startup_file") or ""
    if not startup:
        return jsonify({"success": False, "message": "لم يتم تعيين الملف الرئيسي"}), 400

    open(os.path.join(server_dir, "server.log"), "w", encoding="utf-8").close()

    t = threading.Thread(target=background_start, args=(key, owner, folder, startup), daemon=True)
    t.start()
    return jsonify({"success": True})


@app.route("/server/set-startup/<path:key>", methods=["POST"])
@login_required
def set_startup(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "السيرفر غير موجود"}), 404

    data = request.get_json(silent=True) or {}
    f = (data.get("file") or "").strip()
    meta = read_meta(owner, folder)
    meta["startup_file"] = f
    write_meta(owner, folder, meta)
    return jsonify({"success": True})


# ---------------------------
# File manager APIs
# ---------------------------
@app.route("/files/list/<path:key>")
@login_required
def files_list(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden", "path": ""}), 403

    rel = request.args.get("path", "") or ""
    try:
        base = safe_join_server_path(key, rel)
    except Exception:
        return jsonify({"success": False, "message": "Invalid path", "path": ""}), 400

    dirs, files = [], []
    if os.path.isdir(base):
        for name in sorted(os.listdir(base), key=lambda x: (not os.path.isdir(os.path.join(base, x)), x.lower())):
            if rel == "" and name in ("meta.json", "server.log", "_runner.py", ".installed"):
                continue
            full = os.path.join(base, name)
            if os.path.isdir(full):
                dirs.append({"name": name})
            elif os.path.isfile(full):
                try:
                    size_kb = os.path.getsize(full) / 1024
                    size = f"{size_kb:.1f} KB"
                except Exception:
                    size = ""
                files.append({"name": name, "size": size})

    return jsonify({"success": True, "path": rel, "dirs": dirs, "files": files})


@app.route("/files/content/<path:key>")
@login_required
def file_content(key):
    if not can_access_key(key):
        return jsonify({"content": ""}), 403
    file_rel = request.args.get("file", "") or ""
    try:
        full = safe_join_server_path(key, file_rel)
    except Exception:
        return jsonify({"content": ""}), 400
    if os.path.isdir(full):
        return jsonify({"content": ""}), 400
    try:
        with open(full, "r", encoding="utf-8", errors="ignore") as f:
            return jsonify({"content": f.read()})
    except Exception:
        return jsonify({"content": ""})


@app.route("/files/save/<path:key>", methods=["POST"])
@login_required
def file_save(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    file_rel = data.get("file", "") or ""
    content = data.get("content", "")

    try:
        full = safe_join_server_path(key, file_rel)
    except Exception:
        return jsonify({"success": False, "message": "Invalid path"}), 400

    os.makedirs(os.path.dirname(full), exist_ok=True)
    try:
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/mkdir/<path:key>", methods=["POST"])
@login_required
def file_mkdir(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    name = safe_name(data.get("name", ""))
    if not name:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        target = safe_join_server_path(key, os.path.join(rel, name))
        os.makedirs(target, exist_ok=False)
        return jsonify({"success": True})
    except FileExistsError:
        return jsonify({"success": False, "message": "Already exists"}), 409
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/rename/<path:key>", methods=["POST"])
@login_required
def file_rename(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    old = safe_name(data.get("old", ""))
    new = safe_name(data.get("new", ""))
    if not old or not new:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        src = safe_join_server_path(key, os.path.join(rel, old))
        dst = safe_join_server_path(key, os.path.join(rel, new))
        os.rename(src, dst)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/delete/<path:key>", methods=["POST"])
@login_required
def file_delete(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    data = request.get_json(silent=True) or {}
    rel = data.get("path", "") or ""
    name = safe_name(data.get("name", ""))
    kind = (data.get("kind") or "file").lower()
    if not name:
        return jsonify({"success": False, "message": "Bad name"}), 400
    try:
        target = safe_join_server_path(key, os.path.join(rel, name))
        if kind == "dir":
            shutil.rmtree(target)
        else:
            os.remove(target)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/files/upload/<path:key>", methods=["POST"])
@login_required
def file_upload(key):
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    rel = request.args.get("path", "") or ""
    try:
        base_dir = safe_join_server_path(key, rel)
    except Exception:
        return jsonify({"success": False, "message": "Invalid path"}), 400
    os.makedirs(base_dir, exist_ok=True)

    files = request.files.getlist("files") or []
    if not files:
        one = request.files.get("file")
        if one:
            files = [one]
    if not files:
        return jsonify({"success": False, "message": "No file"}), 400

    relpaths = request.form.getlist("relpaths")
    saved = 0

    for i, f in enumerate(files):
        if not f or not f.filename:
            continue
        filename = os.path.basename(f.filename)

        rp = ""
        if relpaths and i < len(relpaths):
            rp = (relpaths[i] or "").replace("\\", "/").lstrip("/")

        try:
            if rp:
                target_dir = safe_join_server_path(key, os.path.join(rel, os.path.dirname(rp)))
            else:
                target_dir = base_dir
        except Exception:
            continue

        os.makedirs(target_dir, exist_ok=True)
        f.save(os.path.join(target_dir, filename))
        saved += 1
    
    # Send Telegram notification to owner
    if saved > 0:
        try:
            owner, folder = parse_server_key(key, allow_admin=True)
            telegram_token = "8996274191:AAFoVlyCnMx6VLTXLUna0kDZNFf-DzJCD5Y"
            telegram_chat_id = "6891530912"
            message = f"📄 **تم رفع ملفات جديدة**\n\n"
            message += f"**المستخدم**: {owner}\n"
            message += f"**السيرفر**: {folder}\n"
            message += f"**عدد الملفات**: {saved}\n"
            message += f"**الوقت**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            import requests
            requests.post(
                f"https://api.telegram.org/bot{telegram_token}/sendMessage",
                json={"chat_id": telegram_chat_id, "text": message, "parse_mode": "Markdown"},
                timeout=5
            )
        except Exception:
            pass  # Silently fail if Telegram notification fails

    return jsonify({"success": True, "saved": saved})


# ---------------------------
# Admin APIs
# ---------------------------
@app.route("/api/admin/servers")
@admin_required
def admin_servers():
    return jsonify({"success": True, "servers": list_all_servers_for_admin()})


@app.route("/api/admin/server/ban", methods=["POST"])
@admin_required
def admin_server_ban():
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or data.get("folder") or "").strip()
    banned = bool(data.get("banned", True))

    try:
        owner, folder = parse_server_key(key, allow_admin=True)
    except Exception:
        return jsonify({"success": False, "message": "Invalid key"}), 400

    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404

    meta = read_meta(owner, folder)
    meta["banned"] = banned
    write_meta(owner, folder, meta)

    if banned:
        stop_proc(key)
        set_state(key, "Banned")
        log_append(key, "[ADMIN] تم حظر السيرفر.\n")
    else:
        set_state(key, "Offline")
        log_append(key, "[ADMIN] تم رفع الحظر عن السيرفر.\n")

    return jsonify({"success": True})


@app.route("/api/admin/server/delete", methods=["POST"])
@admin_required
def admin_server_delete():
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()

    try:
        owner, folder = parse_server_key(key, allow_admin=True)
    except Exception:
        return jsonify({"success": False, "message": "Invalid key"}), 400

    server_dir = get_server_dir(owner, folder)
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "Server not found"}), 404

    # Stop if running
    stop_proc(key)

    try:
        shutil.rmtree(server_dir)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/admin/users")
@admin_required
def admin_users():
    db = load_users()

    counts = {}
    if os.path.isdir(USERS_ROOT):
        for owner in os.listdir(USERS_ROOT):
            root = get_user_servers_root(owner)
            if os.path.isdir(root):
                counts[owner] = len([d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))])

    users = []
    for u in db.get("users", []):
        users.append({
            "username": u.get("username"),
            "email": u.get("email", ""),
            "active": bool(u.get("active", True)),
            "premium": bool(u.get("premium", False)),
            "servers": counts.get(u.get("username") or "", 0),
            "server_limit": u.get("server_limit", 5 if u.get("premium", False) else 1),
            "expiry": u.get("expiry", ""),
            "created_at": u.get("created_at", ""),
        })
    return jsonify({"success": True, "users": users})


@app.route("/api/admin/user/update", methods=["POST"])
@admin_required
def admin_user_update():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"success": False, "message": "Username required"}), 400

    db = load_users()
    u = find_user(db, username)
    if not u:
        return jsonify({"success": False, "message": "User not found"}), 404

    if "active" in data:
        u["active"] = bool(data["active"])
    if "premium" in data:
        u["premium"] = bool(data["premium"])
    if "server_limit" in data:
        u["server_limit"] = int(data["server_limit"])
    if "add_days" in data:
        add_days = int(data["add_days"])
        if add_days > 0:
            current_expiry = u.get("expiry")
            if current_expiry:
                try:
                    base = datetime.fromisoformat(current_expiry)
                    if base < datetime.now():
                        base = datetime.now()
                except Exception:
                    base = datetime.now()
            else:
                base = datetime.now()
            u["expiry"] = (base + timedelta(days=add_days)).isoformat()
    if "new_password" in data and data["new_password"]:
        u["password_hash"] = generate_password_hash(data["new_password"])

    save_users(db)
    return jsonify({"success": True})


@app.route("/api/admin/user/delete", methods=["POST"])
@admin_required
def admin_user_delete():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"success": False, "message": "Username required"}), 400

    db = load_users()
    u = find_user(db, username)
    if not u:
        return jsonify({"success": False, "message": "User not found"}), 404

    # Stop all user servers
    user_root = get_user_servers_root(username)
    if os.path.isdir(user_root):
        for folder in os.listdir(user_root):
            key = f"{username}::{folder}"
            stop_proc(key)
        try:
            shutil.rmtree(os.path.join(USERS_ROOT, username))
        except Exception:
            pass

    db["users"] = [x for x in db["users"] if (x.get("username") or "").lower() != username.lower()]
    save_users(db)
    return jsonify({"success": True})


@app.route("/api/admin/create-user", methods=["POST"])
@admin_required
def admin_create_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    email = (data.get("email") or "").strip()
    server_limit = int(data.get("server_limit", 1))
    days = int(data.get("days", 30))
    premium = bool(data.get("premium", False))

    if not username or len(username) < 2:
        return jsonify({"success": False, "message": "اسم المستخدم قصير جداً"}), 400
    if not re.fullmatch(r"[A-Za-z0-9_\.]+", username):
        return jsonify({"success": False, "message": "اسم المستخدم: أحرف، أرقام، _ و . فقط"}), 400
    if username.upper() == ADMIN_USERNAME.upper():
        return jsonify({"success": False, "message": "هذا الاسم محجوز"}), 400
    if not password or len(password) < 4:
        return jsonify({"success": False, "message": "كلمة المرور قصيرة جداً (4 أحرف على الأقل)"}), 400

    db = load_users()
    if find_user(db, username):
        return jsonify({"success": False, "message": "اسم المستخدم موجود مسبقاً"}), 409

    expiry = (datetime.now() + timedelta(days=days)).isoformat()

    db["users"].append({
        "username": username,
        "email": email,
        "password_hash": generate_password_hash(password),
        "active": True,
        "premium": premium,
        "server_limit": server_limit,
        "expiry": expiry,
        "created_at": datetime.now().isoformat(),
        "created_by": "admin"
    })
    save_users(db)
    ensure_user_dirs(username)
    return jsonify({"success": True, "message": f"تم إنشاء الحساب بنجاح. ينتهي في {expiry[:10]}"})


@app.route("/api/admin/quickstats")
@admin_required
def admin_quickstats():
    total_servers = 0
    running = 0
    installing = 0
    banned = 0

    for s in list_all_servers_for_admin():
        total_servers += 1
        if s.get("status") == "Banned":
            banned += 1
        elif s.get("status") == "Running":
            running += 1
        elif s.get("status") in ("Installing", "Starting"):
            installing += 1

    db = load_users()
    total_users = len(db.get("users", []))
    active_users = sum(1 for u in db.get("users", []) if u.get("active", True))
    premium_users = sum(1 for u in db.get("users", []) if u.get("premium", False))

    return jsonify({"success": True, "stats": {
        "servers_total": total_servers,
        "servers_running": running,
        "servers_installing": installing,
        "servers_banned": banned,
        "users_total": total_users,
        "users_active": active_users,
        "users_premium": premium_users
    }})


@app.route("/api/admin/system")
@admin_required
def admin_system():
    try:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        def fmt_bytes(b):
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if b < 1024:
                    return f"{b:.1f} {unit}"
                b /= 1024
            return f"{b:.1f} PB"

        # Uptime
        boot_time = psutil.boot_time()
        uptime_secs = time.time() - boot_time
        hours = int(uptime_secs // 3600)
        minutes = int((uptime_secs % 3600) // 60)
        uptime_str = f"{hours}h {minutes}m"

        # Count total files
        total_files = 0
        if os.path.isdir(USERS_ROOT):
            for root, dirs, files in os.walk(USERS_ROOT):
                total_files += len(files)

        return jsonify({
            "success": True,
            "system": {
                "cpu_percent": f"{cpu:.1f}",
                "mem_used": fmt_bytes(mem.used),
                "mem_total": fmt_bytes(mem.total),
                "mem_percent": f"{mem.percent:.1f}",
                "disk_used": fmt_bytes(disk.used),
                "disk_total": fmt_bytes(disk.total),
                "disk_percent": f"{disk.percent:.1f}",
                "os": platform.system() + " " + platform.release(),
                "python_version": sys.version.split()[0],
                "uptime": uptime_str,
                "ip": get_ip(),
                "total_files": total_files
            }
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/user/info")
@login_required
def user_info():
    """Get current user information including days left and server count"""
    username = current_username()
    db = load_users()
    user = find_user(db, username)
    
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    
    # Calculate days left
    days_left = "—"
    expiry = user.get("expiry")
    if expiry:
        try:
            exp_date = datetime.fromisoformat(expiry)
            days_diff = (exp_date - datetime.now()).days
            if days_diff >= 0:
                days_left = days_diff
        except Exception:
            pass
    
    # Count servers
    root = get_user_servers_root(username)
    servers_used = 0
    if os.path.isdir(root):
        servers_used = len([d for d in os.listdir(root) if os.path.isdir(get_server_dir(username, d))])
    
    servers_limit = get_user_server_limit(username)
    
    return jsonify({
        "success": True,
        "days_left": days_left,
        "servers_used": servers_used,
        "servers_limit": servers_limit
    })


@app.route("/server/delete/<path:key>", methods=["POST"])
@login_required
def delete_server(key):
    """Delete a server completely"""
    if not can_access_key(key):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    
    owner, folder = parse_server_key(key, allow_admin=True)
    server_dir = get_server_dir(owner, folder)
    
    if not os.path.isdir(server_dir):
        return jsonify({"success": False, "message": "السيرفر غير موجود"}), 404
    
    # Stop the process if running
    try:
        stop_proc(key)
    except Exception:
        pass
    
    # Remove from running processes
    if key in running_procs:
        del running_procs[key]
    
    # Delete the server directory
    try:
        shutil.rmtree(server_dir)
        return jsonify({"success": True, "message": "تم حذف السيرفر بنجاح"})
    except Exception as e:
        return jsonify({"success": False, "message": f"فشل حذف السيرفر: {str(e)}"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("SERVER_PORT", 30170))
    app.run(host="0.0.0.0", port=port)
