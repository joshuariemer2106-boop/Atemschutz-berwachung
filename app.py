from flask import Flask, render_template, request, redirect, flash, url_for, session, send_from_directory
import os
import requests
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import re
import json
from datetime import datetime, timezone
import time
from contextlib import contextmanager
import uuid

load_dotenv()
WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
WEBHOOK_URL_2 = os.getenv("DISCORD_WEBHOOK_URL_2")
PRESS_PASSWORD = (os.getenv("PRESSE_PASSWORD") or "presse123").strip()
PRESS_LEITUNG_PASSWORD = (os.getenv("PRESSE_LEITUNG_PASSWORD") or PRESS_PASSWORD).strip()
PRESS_MITGLIED_PASSWORD = (os.getenv("PRESSE_MITGLIED_PASSWORD") or PRESS_PASSWORD).strip()

BASE_DIR = os.path.dirname(__file__)
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif"}
PRESS_STORAGE_DIR = os.getenv("PRESS_STORAGE_DIR", BASE_DIR).strip() or BASE_DIR
os.makedirs(PRESS_STORAGE_DIR, exist_ok=True)
PRESS_ARTICLES_FILE = os.path.join(PRESS_STORAGE_DIR, "press_articles.json")
PRESS_USERS_FILE = os.path.join(PRESS_STORAGE_DIR, "press_users.json")
PRESS_SETTINGS_FILE = os.path.join(PRESS_STORAGE_DIR, "press_settings.json")
PRESS_SERVERS_FILE = os.path.join(PRESS_STORAGE_DIR, "press_servers.json")

PERMISSIONS_CATALOG = [
    ("atemschutz_access", "Zugriff auf Atemschutz"),
    ("presse_access", "Zugriff auf Presse-Bereich"),
    ("staff_list_access", "Zugriff auf Mitarbeiterliste"),
    ("create_users", "Mitarbeiter erstellen"),
    ("approve_articles", "Artikel freigeben"),
]

DEFAULT_ROLE_CONFIGS = {
    "owner": {
        "label": "Owner",
        "permissions": [perm for perm, _ in PERMISSIONS_CATALOG],
    },
    "leitung": {
        "label": "Leitung",
        "permissions": ["atemschutz_access", "presse_access", "staff_list_access", "create_users", "approve_articles"],
    },
    "mitglied": {
        "label": "Presse Mitglied",
        "permissions": ["atemschutz_access", "presse_access", "staff_list_access"],
    },
    "asw": {
        "label": "Atemschutz",
        "permissions": ["atemschutz_access"],
    },
}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = os.getenv("FLASK_SECRET", "dev-secret")


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def get_webhook_urls():
    settings = load_press_settings_for(current_server_id())
    asw_url_1 = (settings.get("asw_webhook_url_1", "") or "").strip()
    asw_url_2 = (settings.get("asw_webhook_url_2", "") or "").strip()
    if not asw_url_1 and not asw_url_2:
        asw_url_1 = WEBHOOK_URL or ""
        asw_url_2 = WEBHOOK_URL_2 or ""
    return [url for url in [asw_url_1, asw_url_2] if url]


def get_press_webhook_urls():
    settings = load_press_settings_for(current_server_id())
    press_url_1 = (settings.get("webhook_url_1", "") or "").strip()
    press_url_2 = (settings.get("webhook_url_2", "") or "").strip()
    if not press_url_1 and not press_url_2:
        press_url_1 = os.getenv("DISCORD_PRESS_WEBHOOK_URL", "")
        press_url_2 = os.getenv("DISCORD_PRESS_WEBHOOK_URL_2", "")
    return [url for url in [press_url_1, press_url_2] if url]


@contextmanager
def file_lock(lock_path, timeout_sec=8):
    start = time.time()
    lock_fd = None
    while True:
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            break
        except FileExistsError:
            if (time.time() - start) > timeout_sec:
                raise TimeoutError(f"Lock timeout for {lock_path}")
            time.sleep(0.1)
    try:
        yield
    finally:
        try:
            if lock_fd is not None:
                os.close(lock_fd)
            if os.path.exists(lock_path):
                os.remove(lock_path)
        except Exception:
            pass


def load_press_articles():
    if not os.path.exists(PRESS_ARTICLES_FILE):
        return []
    try:
        with open(PRESS_ARTICLES_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_press_articles(articles):
    lock_path = PRESS_ARTICLES_FILE + ".lock"
    with file_lock(lock_path):
        tmp_path = PRESS_ARTICLES_FILE + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(articles, fh, ensure_ascii=False, indent=2)
        os.replace(tmp_path, PRESS_ARTICLES_FILE)


def is_press_logged_in():
    return bool(session.get("presse_auth"))


def get_press_role():
    return session.get("presse_role", "")


def current_server_id():
    return session.get("server_id", "")


def load_press_servers():
    if not os.path.exists(PRESS_SERVERS_FILE):
        return []
    try:
        with open(PRESS_SERVERS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_press_servers(servers):
    lock_path = PRESS_SERVERS_FILE + ".lock"
    with file_lock(lock_path):
        tmp_path = PRESS_SERVERS_FILE + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(servers, fh, ensure_ascii=False, indent=2)
        os.replace(tmp_path, PRESS_SERVERS_FILE)


def find_server_by_code(servers, server_code):
    code = (server_code or "").strip().lower()
    return next((s for s in servers if (s.get("server_code", "").strip().lower() == code)), None)


def find_server_by_id(servers, server_id):
    sid = (server_id or "").strip()
    return next((s for s in servers if (s.get("id", "").strip() == sid)), None)


def ensure_storage_migrated():
    servers = load_press_servers()
    users = load_press_users()
    settings_list = load_press_settings()

    users_need_server = any(not u.get("server_id") for u in users)
    settings_need_server = any(not s.get("server_id") for s in settings_list)
    if not users_need_server and not settings_need_server:
        return

    default_server = find_server_by_code(servers, "default")
    if not default_server:
        owner_username = next((u.get("username", "") for u in users if u.get("role") == "owner"), "")
        default_server = {
            "id": str(uuid.uuid4()),
            "name": "Standard Server",
            "server_code": "default",
            "created_at": datetime.now().strftime("%d.%m.%Y %H:%M"),
            "owner_username": owner_username,
        }
        servers.append(default_server)
        save_press_servers(servers)

    default_server_id = default_server.get("id", "")
    changed_users = False
    for user in users:
        if not user.get("server_id"):
            user["server_id"] = default_server_id
            changed_users = True
    if changed_users:
        save_press_users(users)

    changed_settings = False
    for settings in settings_list:
        if not settings.get("server_id"):
            settings["server_id"] = default_server_id
            changed_settings = True
    if changed_settings:
        save_press_settings(settings_list)


def load_press_settings():
    if not os.path.exists(PRESS_SETTINGS_FILE):
        return []
    try:
        with open(PRESS_SETTINGS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            if isinstance(data, list):
                return data
            # Backward compatibility: old installations stored a single dict.
            if isinstance(data, dict):
                return [data]
            return []
    except Exception:
        return []


def save_press_settings(settings_list):
    lock_path = PRESS_SETTINGS_FILE + ".lock"
    with file_lock(lock_path):
        tmp_path = PRESS_SETTINGS_FILE + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(settings_list, fh, ensure_ascii=False, indent=2)
        os.replace(tmp_path, PRESS_SETTINGS_FILE)


def load_press_settings_for(server_id):
    if not server_id:
        return {}
    settings_list = load_press_settings()
    return next((s for s in settings_list if s.get("server_id") == server_id), {})


def save_press_settings_for(server_id, settings):
    if not server_id:
        return
    settings_list = load_press_settings()
    settings["server_id"] = server_id
    idx = next((i for i, s in enumerate(settings_list) if s.get("server_id") == server_id), -1)
    if idx >= 0:
        settings_list[idx] = settings
    else:
        settings_list.append(settings)
    save_press_settings(settings_list)


def load_press_users():
    if not os.path.exists(PRESS_USERS_FILE):
        return []
    try:
        with open(PRESS_USERS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_press_users(users):
    lock_path = PRESS_USERS_FILE + ".lock"
    with file_lock(lock_path):
        tmp_path = PRESS_USERS_FILE + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(users, fh, ensure_ascii=False, indent=2)
        os.replace(tmp_path, PRESS_USERS_FILE)


def find_press_user(users, username):
    username = (username or "").strip().lower()
    return next(
        (
            u
            for u in users
            if (u.get("username", "").strip().lower() == username)
            or (u.get("display_name", "").strip().lower() == username)
        ),
        None,
    )


def owner_exists(users=None):
    users = users if users is not None else load_press_users()
    return any((u.get("role") == "owner") for u in users)


def format_press_message(article):
    return (
        f"ðŸ“° Presse-Freigabe\n\n"
        f"Titel: {article.get('title', '')}\n"
        f"Von: {article.get('author_name', 'Unbekannt')} ({article.get('author_role', '')})\n"
        f"Erstellt: {article.get('created_at', '')}\n\n"
        f"{article.get('body', '')}"
    )


def get_safe_next(default_path):
    next_path = request.values.get("next", "").strip()
    if next_path.startswith("/") and not next_path.startswith("//"):
        return next_path
    return default_path


def get_role_configs(server_id):
    configs = {
        key: {"label": value.get("label", key), "permissions": list(value.get("permissions", []))}
        for key, value in DEFAULT_ROLE_CONFIGS.items()
    }
    settings = load_press_settings_for(server_id)
    raw = settings.get("role_configs", {})
    if isinstance(raw, dict):
        for role_key, role_cfg in raw.items():
            if not isinstance(role_cfg, dict):
                continue
            key = (role_key or "").strip().lower()
            if not key:
                continue
            label = (role_cfg.get("label", key) or key).strip()
            permissions = role_cfg.get("permissions", [])
            if not isinstance(permissions, list):
                permissions = []
            valid_permissions = [p for p in permissions if any(p == code for code, _ in PERMISSIONS_CATALOG)]
            configs[key] = {"label": label, "permissions": valid_permissions}
    # Owner remains full-access by design.
    configs["owner"] = {
        "label": configs.get("owner", {}).get("label", "Owner"),
        "permissions": [perm for perm, _ in PERMISSIONS_CATALOG],
    }
    return configs


def save_role_configs_for(server_id, role_configs):
    settings = load_press_settings_for(server_id)
    settings["role_configs"] = role_configs
    save_press_settings_for(server_id, settings)


def has_permission(permission_code, role=None, server_id=None):
    role = (role or get_press_role() or "").strip().lower()
    server_id = server_id or current_server_id()
    if not role:
        return False
    role_configs = get_role_configs(server_id)
    cfg = role_configs.get(role, {})
    return permission_code in cfg.get("permissions", [])


def has_press_access():
    return has_permission("presse_access")


def count_server_owners(users, server_id):
    return sum(1 for u in users if u.get("server_id") == server_id and u.get("role") == "owner")


@app.route("/", methods=["GET"])
def start():
    ensure_storage_migrated()
    return render_template(
        "server_entry.html",
        logged_in=is_press_logged_in(),
        role=get_press_role(),
        name=session.get("presse_name", ""),
    )


@app.route("/menu", methods=["GET"])
def menu():
    if not is_press_logged_in():
        return redirect(url_for("start"))
    server_id = current_server_id()
    role = get_press_role()
    role_configs = get_role_configs(server_id)
    return render_template(
        "menu.html",
        role=role,
        role_label=role_configs.get(role, {}).get("label", role),
        server_name=session.get("server_name", ""),
        server_code=session.get("server_code", ""),
        can_access_press=has_permission("presse_access", role=role, server_id=server_id),
        can_access_staff_list=has_permission("staff_list_access", role=role, server_id=server_id),
        can_access_owner_settings=(role == "owner"),
    )


@app.route("/mitarbeiter", methods=["GET"])
def mitarbeiterliste():
    if not is_press_logged_in():
        return redirect("/presse")
    if not has_permission("staff_list_access"):
        flash("Kein Zugriff auf Mitarbeiterliste.", "danger")
        return redirect("/menu")

    server_id = current_server_id()
    role = get_press_role()
    users = [u for u in load_press_users() if u.get("server_id") == server_id]
    users.sort(key=lambda u: (u.get("display_name", "").lower(), u.get("username", "").lower()))
    role_configs = get_role_configs(server_id)
    return render_template(
        "mitarbeiterliste.html",
        role=role,
        role_label=role_configs.get(role, {}).get("label", role),
        username=session.get("presse_username", ""),
        users=users,
        can_manage_users=has_permission("create_users", role=role, server_id=server_id),
        role_configs=role_configs,
    )

# Compatibility route for direct template URL usage (e.g. Live Server style links)
@app.route("/templates/menu.html", methods=["GET"])
def menu_template_alias():
    return redirect("/menu")


@app.route("/templates/mitarbeiterliste.html", methods=["GET"])
def mitarbeiterliste_template_alias():
    return redirect("/mitarbeiter")


@app.route("/uploads/<path:filename>", methods=["GET"])
def uploaded_file(filename):
    if not is_press_logged_in():
        return redirect("/presse")
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/join", methods=["GET", "POST"])
def join():
    ensure_storage_migrated()
    if request.method == "POST":
        server_code = request.form.get("server_code", "").strip().lower()
        username = request.form.get("username", "").strip().lower()
        display_name = request.form.get("display_name", "").strip()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")

        servers = load_press_servers()
        server = find_server_by_code(servers, server_code)
        users = load_press_users()
        if not server or not username or not display_name or not password:
            flash("Alle Felder sind erforderlich.", "danger")
            return redirect("/join")
        if password != password_confirm:
            flash("Passwörter stimmen nicht überein.", "danger")
            return redirect("/join")
        if next((u for u in users if u.get("server_id") == server.get("id") and u.get("username", "").strip().lower() == username), None):
            flash("Benutzername bereits vergeben.", "danger")
            return redirect("/join")

        users.append(
            {
                "username": username,
                "display_name": display_name,
                "role": "asw",
                "server_id": server.get("id"),
                "password_hash": generate_password_hash(password),
                "created_at": datetime.now().strftime("%d.%m.%Y %H:%M"),
            }
        )
        save_press_users(users)

        session["presse_auth"] = True
        session["presse_role"] = "asw"
        session["presse_name"] = display_name
        session["presse_username"] = username
        session["server_id"] = server.get("id")
        session["server_code"] = server.get("server_code")
        session["server_name"] = server.get("name")
        flash("Beitritt erfolgreich. Zugriff auf Atemschutz ist freigeschaltet.", "success")
        return redirect("/atemschutz")

    return render_template("join.html")


@app.route("/atemschutz", methods=["GET", "POST"])
def atemschutz():
    if not is_press_logged_in():
        return redirect(url_for("presse_login", next="/atemschutz"))
    if not has_permission("atemschutz_access"):
        flash("Kein Zugriff auf Atemschutz.", "danger")
        return redirect("/menu")

    if request.method == "POST":
        # check if it's a screenshot upload
        screenshot = request.files.get('screenshot')
        if screenshot and screenshot.filename:
            # This is an auto-screenshot from browser
            try:
                filename = secure_filename(f"screenshot_{os.urandom(4).hex()}.png")
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                screenshot.save(filepath)
                
                webhook_urls = get_webhook_urls()
                if webhook_urls:
                    ok_count = 0
                    errors = []
                    for idx, url in enumerate(webhook_urls, start=1):
                        with open(filepath, 'rb') as fh:
                            files = {'file': (filename, fh, 'image/png')}
                            resp = requests.post(url, files=files, timeout=20)
                        if resp.status_code in (200, 204):
                            ok_count += 1
                        else:
                            errors.append(f"Webhook {idx}: {resp.status_code}")

                    if ok_count > 0:
                        message = "Screenshot erfolgreich gesendet"
                        if errors:
                            message += " (teilweise, " + ", ".join(errors) + ")"
                        return {'status': 'success', 'message': message}, 200
                    return {'status': 'error', 'message': ", ".join(errors)}, 500
                else:
                    return {'status': 'error', 'message': 'Keine Webhook-URL gesetzt'}, 500
            except Exception as e:
                return {'status': 'error', 'message': str(e)}, 500
            finally:
                try:
                    if 'filepath' in locals():
                        os.remove(filepath)
                except:
                    pass
        
        # Fall-back: old text-based form submission (kept for compatibility)
        fields = {}
        for k in [
            "name",
            "uhrzeit",
            "einsatznummer",
            "anfangsdruck",
            "zwischendruck",
            "enddruck",
            "fahrzeug",
            "asw_name",
        ]:
            fields[k] = request.form.get(k, "").strip()

        file = request.files.get("foto")
        filename = None
        saved_path = None
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            saved_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(saved_path)

        mapping = {
            "name": "Name",
            "uhrzeit": "Uhrzeit",
            "einsatznummer": "Einsatznummer",
            "anfangsdruck": "Anfangsdruck",
            "zwischendruck": "Zwischendruck",
            "enddruck": "Enddruck",
            "fahrzeug": "Fahrzeug",
            "asw_name": "Atemschutzüberwachung",
        }

        content_lines = []
        for k, label in mapping.items():
            if fields.get(k):
                content_lines.append(f"{label}: {fields[k]}")

        # parse dynamic trupps[...] fields from form (keys like trupps[0][members][0][name])
        trupps = {}
        pattern = re.compile(r'^trupps\[(\d+)\]\[members\]\[(\d+)\]\[(\w+)\]$')
        for key, val in request.form.items():
            m = pattern.match(key)
            if m:
                ti = int(m.group(1))
                mi = int(m.group(2))
                field = m.group(3)
                trupps.setdefault(ti, {}).setdefault('members', {}).setdefault(mi, {})[field] = val.strip()

        if trupps:
            for ti in sorted(trupps.keys()):
                content_lines.append(f"--- Trupp {ti+1} ---")
                members = trupps[ti].get('members', {})
                for mi in sorted(members.keys()):
                    mem = members[mi]
                    name = mem.get('name', '')
                    start = mem.get('start', '')
                    rest = mem.get('rest', '')
                    end = mem.get('end', '')
                    parts = []
                    if name: parts.append(f"Name: {name}")
                    if start: parts.append(f"Startdruck: {start} bar")
                    if rest: parts.append(f"Restdruck: {rest} bar")
                    if end: parts.append(f"Endzeit: {end}")
                    if parts:
                        content_lines.append(" | ".join(parts))

        # bemerkungen (optional)
        bemerk = request.form.get('bemerkungen', '').strip()
        if bemerk:
            content_lines.append('Bemerkungen: ' + bemerk)

        content = "\n".join(content_lines) if content_lines else "Neuer Atemschutz-Eintrag"

        webhook_urls = get_webhook_urls()
        if webhook_urls:
            data = {"content": content}
            ok_count = 0
            errors = []
            try:
                for idx, url in enumerate(webhook_urls, start=1):
                    if saved_path:
                        with open(saved_path, "rb") as fh:
                            files = {"file": (filename, fh, file.mimetype)}
                            resp = requests.post(url, data=data, files=files, timeout=10)
                    else:
                        resp = requests.post(url, data=data, timeout=10)

                    if resp.status_code in (200, 204):
                        ok_count += 1
                    else:
                        errors.append(f"Webhook {idx}: {resp.status_code}")

                if ok_count > 0:
                    msg = f"Eintrag an {ok_count} Webhook(s) gesendet."
                    if errors:
                        msg += " Fehler: " + ", ".join(errors)
                    flash(msg, "success")
                else:
                    flash("Webhook-Fehler: " + ", ".join(errors), "danger")
            except Exception as e:
                flash(f"Fehler beim Senden an Webhook: {e}", "danger")
            finally:
                if saved_path:
                    try:
                        os.remove(saved_path)
                    except Exception:
                        pass
        else:
            flash("Keine DISCORD_WEBHOOK_URL gesetzt. Setze die Umgebungsvariable.", "warning")

        return redirect(url_for("atemschutz"))

    return render_template(
        "index.html",
        user_name=session.get("presse_name", "Unbekannt"),
        user_role=session.get("presse_role", ""),
    )


# Compatibility route for direct template URL usage (e.g. Live Server style links)
@app.route("/templates/index.html", methods=["GET"])
def atemschutz_template_alias():
    return redirect("/atemschutz")


@app.route("/presse", methods=["GET", "POST"])
def presse_login():
    ensure_storage_migrated()
    users = load_press_users()
    servers = load_press_servers()
    if request.method == "POST":
        server_code = request.form.get("server_code", "").strip().lower()
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        server = find_server_by_code(servers, server_code)

        # Account-based login with server-code (preferred)
        user = None
        if server:
            user = next(
                (
                    u
                    for u in users
                    if u.get("server_id") == server.get("id")
                    and (
                        (u.get("username", "").strip().lower() == username)
                        or (u.get("display_name", "").strip().lower() == username)
                    )
                ),
                None,
            )

        # Fallback login without server-code for convenience after logout:
        # if exactly one user matches name+password globally, use that account.
        if not user and not server_code:
            candidates = [
                u
                for u in users
                if (
                    (u.get("username", "").strip().lower() == username)
                    or (u.get("display_name", "").strip().lower() == username)
                )
                and check_password_hash(u.get("password_hash", ""), password)
            ]
            if len(candidates) == 1:
                user = candidates[0]
                server = find_server_by_id(servers, user.get("server_id", ""))
            elif len(candidates) > 1:
                flash("Mehrere Konten gefunden. Bitte Server-Code eingeben.", "warning")
                return redirect("/presse")

        if user and check_password_hash(user.get("password_hash", ""), password):
            session["presse_auth"] = True
            session["presse_role"] = user.get("role", "mitglied")
            session["presse_name"] = user.get("display_name", user.get("username", "Unbekannt"))
            session["presse_username"] = user.get("username", "")
            session["server_id"] = user.get("server_id", "")
            session["server_code"] = server.get("server_code", "") if server else ""
            session["server_name"] = server.get("name", "") if server else ""
            default_target = "/atemschutz" if session["presse_role"] == "asw" else "/menu"
            return redirect(get_safe_next(default_target))

        # Legacy fallback (env-based) remains for compatibility
        role = request.form.get("role", "").strip().lower()
        name = request.form.get("name", "").strip() or "Unbekannt"
        valid_legacy = (
            (role == "leitung" and password == PRESS_LEITUNG_PASSWORD)
            or (role == "mitglied" and password == PRESS_MITGLIED_PASSWORD)
        )
        if valid_legacy:
            session["presse_auth"] = True
            session["presse_role"] = role
            session["presse_name"] = name
            session["presse_username"] = ""
            return redirect(get_safe_next("/menu"))

        return redirect("/presse?error=1")
    return render_template(
        "presse_login.html",
        error=request.args.get("error") == "1",
        owner_exists=owner_exists(users),
        next_path=get_safe_next(""),
    )


@app.route("/presse/owner/setup", methods=["GET", "POST"])
def presse_owner_setup():
    ensure_storage_migrated()
    users = load_press_users()
    servers = load_press_servers()

    if request.method == "POST":
        server_name = request.form.get("server_name", "").strip()
        server_code = request.form.get("server_code", "").strip().lower()
        username = request.form.get("username", "").strip().lower()
        display_name = request.form.get("display_name", "").strip()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")
        webhook_url_1 = request.form.get("webhook_url_1", "").strip()
        webhook_url_2 = request.form.get("webhook_url_2", "").strip()

        if not server_name or not server_code or not username or not display_name or not password or not webhook_url_1:
            flash("Alle Pflichtfelder inklusive Webhook sind erforderlich.", "danger")
            return redirect("/presse/owner/setup")
        if password != password_confirm:
            flash("Passwörter stimmen nicht überein.", "danger")
            return redirect("/presse/owner/setup")
        if find_server_by_code(servers, server_code):
            flash("Server-Code existiert bereits.", "danger")
            return redirect("/presse/owner/setup")
        if next((u for u in users if u.get("username", "").strip().lower() == username), None):
            flash("Benutzername existiert bereits.", "danger")
            return redirect("/presse/owner/setup")

        server_id = str(uuid.uuid4())
        servers.append(
            {
                "id": server_id,
                "name": server_name,
                "server_code": server_code,
                "created_at": datetime.now().strftime("%d.%m.%Y %H:%M"),
                "owner_username": username,
            }
        )
        save_press_servers(servers)

        users.append(
            {
                "username": username,
                "display_name": display_name,
                "role": "owner",
                "server_id": server_id,
                "password_hash": generate_password_hash(password),
                "created_at": datetime.now().strftime("%d.%m.%Y %H:%M"),
            }
        )
        save_press_users(users)
        save_press_settings_for(
            server_id,
            {
                "server_id": server_id,
                "webhook_url_1": webhook_url_1,
                "webhook_url_2": webhook_url_2,
                "updated_at": datetime.now().strftime("%d.%m.%Y %H:%M"),
                "updated_by": username,
            }
        )
        flash("Owner-Account erstellt. Bitte einloggen.", "success")
        return redirect("/presse")

    return render_template("presse_owner_setup.html")


@app.route("/presse/bereich", methods=["GET"])
def presse_bereich():
    if not is_press_logged_in():
        return redirect("/presse")
    if not has_press_access():
        flash("Kein Zugriff auf Presse-Bereich.", "danger")
        return redirect("/menu")
    role = get_press_role()
    server_id = current_server_id()
    role_configs = get_role_configs(server_id)
    articles = load_press_articles()
    server_articles = [a for a in articles if a.get("server_id") == server_id]
    pending_articles = [a for a in server_articles if a.get("status") == "pending"]
    approved_articles = [a for a in server_articles if a.get("status") == "approved"]
    server_users = [u for u in load_press_users() if u.get("server_id") == server_id]
    server_users.sort(key=lambda u: (u.get("display_name", "").lower(), u.get("username", "").lower()))
    approved_articles.sort(key=lambda a: a.get("approved_at", ""), reverse=True)
    pending_articles.sort(key=lambda a: a.get("created_at", ""), reverse=True)

    return render_template(
        "presse_bereich.html",
        role=role,
        role_label=role_configs.get(role, {}).get("label", role),
        name=session.get("presse_name", "Unbekannt"),
        username=session.get("presse_username", ""),
        pending_articles=pending_articles,
        approved_articles=approved_articles,
        users=server_users,
        can_manage_users=has_permission("create_users", role=role, server_id=server_id),
        can_approve_articles=has_permission("approve_articles", role=role, server_id=server_id),
        role_configs=role_configs,
        press_settings=load_press_settings_for(server_id),
    )


@app.route("/presse/user/create", methods=["POST"])
def presse_user_create():
    if not is_press_logged_in():
        return redirect("/presse")
    if not has_permission("staff_list_access"):
        flash("Kein Zugriff auf Nutzerverwaltung.", "danger")
        return redirect("/menu")
    actor_role = get_press_role()
    server_id = current_server_id()
    if not has_permission("create_users", role=actor_role, server_id=server_id):
        flash("Du darfst keine Accounts erstellen.", "danger")
        return redirect("/presse/bereich")

    users = load_press_users()
    role_configs = get_role_configs(server_id)
    username = request.form.get("username", "").strip().lower()
    display_name = request.form.get("display_name", "").strip()
    role = request.form.get("role", "").strip().lower()
    password = request.form.get("password", "")
    password_confirm = request.form.get("password_confirm", "")

    allowed_roles = set(role_configs.keys())
    if actor_role != "owner":
        allowed_roles.discard("owner")
    if role not in allowed_roles:
        flash("Ungültige Rolle.", "danger")
        return redirect("/presse/bereich")
    if not username or not display_name or not password:
        flash("Alle Felder für neuen Account sind erforderlich.", "danger")
        return redirect("/presse/bereich")
    if password != password_confirm:
        flash("Passwörter stimmen nicht überein.", "danger")
        return redirect("/presse/bereich")
    existing = next((u for u in users if u.get("server_id") == server_id and u.get("username", "").strip().lower() == username), None)
    if existing:
        flash("Benutzername bereits vergeben.", "danger")
        return redirect("/presse/bereich")

    users.append(
        {
            "username": username,
            "display_name": display_name,
            "role": role,
            "server_id": server_id,
            "password_hash": generate_password_hash(password),
            "created_at": datetime.now().strftime("%d.%m.%Y %H:%M"),
        }
    )
    save_press_users(users)
    flash(f"Account '{username}' erstellt.", "success")
    return redirect("/presse/bereich")


@app.route("/presse/user/<username>/role", methods=["POST"])
def presse_user_update_role(username):
    if not is_press_logged_in():
        return redirect("/presse")
    if not has_permission("staff_list_access"):
        flash("Kein Zugriff auf Nutzerverwaltung.", "danger")
        return redirect("/menu")

    actor_role = get_press_role()
    server_id = current_server_id()
    if not has_permission("create_users", role=actor_role, server_id=server_id):
        flash("Du darfst Rollen nicht ändern.", "danger")
        return redirect("/presse/bereich")

    users = load_press_users()
    role_configs = get_role_configs(server_id)
    target = next(
        (
            u
            for u in users
            if u.get("server_id") == server_id
            and u.get("username", "").strip().lower() == (username or "").strip().lower()
        ),
        None,
    )
    if not target:
        flash("Mitarbeiter nicht gefunden.", "danger")
        return redirect("/presse/bereich")

    actor_username = session.get("presse_username", "").strip().lower()
    if target.get("username", "").strip().lower() == actor_username:
        flash("Eigene Rolle kann hier nicht geändert werden.", "warning")
        return redirect("/presse/bereich")

    new_role = request.form.get("new_role", "").strip().lower()
    allowed_target_roles = set(role_configs.keys())
    if actor_role != "owner":
        allowed_target_roles.discard("owner")
    if new_role not in allowed_target_roles:
        flash("Ungültige Zielrolle.", "danger")
        return redirect("/presse/bereich")

    old_role = target.get("role", "")
    if old_role == "owner" and new_role != "owner":
        if count_server_owners(users, server_id) <= 1:
            flash("Mindestens ein Owner pro Wache muss bestehen bleiben.", "danger")
            return redirect("/presse/bereich")

    target["role"] = new_role
    save_press_users(users)
    flash(f"Rolle von '{target.get('username')}' geändert: {old_role} -> {new_role}.", "success")
    return redirect("/presse/bereich")


@app.route("/presse/settings/webhook", methods=["POST"])
def presse_settings_webhook():
    return redirect("/owner/settings")


@app.route("/owner/settings", methods=["GET", "POST"])
def owner_settings():
    if not is_press_logged_in():
        return redirect("/presse")
    if get_press_role() != "owner":
        flash("Nur Owner darf diese Einstellungen ändern.", "danger")
        return redirect("/menu")

    server_id = current_server_id()
    role_configs = get_role_configs(server_id)
    if request.method == "POST":
        action = request.form.get("action", "save_webhooks").strip().lower()

        if action == "save_role":
            role_key = re.sub(r"[^a-z0-9_-]", "", request.form.get("role_key", "").strip().lower())
            role_label = request.form.get("role_label", "").strip()
            selected_permissions = request.form.getlist("permissions")
            valid_permission_codes = {code for code, _ in PERMISSIONS_CATALOG}
            permissions = [p for p in selected_permissions if p in valid_permission_codes]

            if not role_key:
                flash("Rollen-ID ist erforderlich (z.B. presse_mitglied).", "danger")
                return redirect("/owner/settings")
            if role_key == "owner":
                flash("Owner-Rolle kann nicht geändert werden.", "danger")
                return redirect("/owner/settings")
            if not role_label:
                role_label = role_key

            role_configs[role_key] = {"label": role_label, "permissions": permissions}
            save_role_configs_for(server_id, role_configs)
            flash(f"Rolle '{role_label}' gespeichert.", "success")
            return redirect("/owner/settings")

        asw_webhook_url_1 = request.form.get("asw_webhook_url_1", "").strip()
        asw_webhook_url_2 = request.form.get("asw_webhook_url_2", "").strip()
        webhook_url_1 = request.form.get("webhook_url_1", "").strip()
        webhook_url_2 = request.form.get("webhook_url_2", "").strip()

        if not asw_webhook_url_1:
            flash("Atemschutz Webhook URL 1 ist erforderlich.", "danger")
            return redirect("/owner/settings")
        if not webhook_url_1:
            flash("Presse Webhook URL 1 ist erforderlich.", "danger")
            return redirect("/owner/settings")

        save_press_settings_for(
            server_id,
            {
                "server_id": server_id,
                "asw_webhook_url_1": asw_webhook_url_1,
                "asw_webhook_url_2": asw_webhook_url_2,
                "webhook_url_1": webhook_url_1,
                "webhook_url_2": webhook_url_2,
                "role_configs": role_configs,
                "updated_at": datetime.now().strftime("%d.%m.%Y %H:%M"),
                "updated_by": session.get("presse_username", ""),
            }
        )
        flash("Owner Einstellungen gespeichert.", "success")
        return redirect("/owner/settings")

    settings = load_press_settings_for(server_id)
    if not settings.get("asw_webhook_url_1"):
        settings["asw_webhook_url_1"] = WEBHOOK_URL or ""
    if not settings.get("asw_webhook_url_2"):
        settings["asw_webhook_url_2"] = WEBHOOK_URL_2 or ""
    if not settings.get("webhook_url_1"):
        settings["webhook_url_1"] = os.getenv("DISCORD_PRESS_WEBHOOK_URL", "")
    if not settings.get("webhook_url_2"):
        settings["webhook_url_2"] = os.getenv("DISCORD_PRESS_WEBHOOK_URL_2", "")

    return render_template(
        "owner_settings.html",
        settings=settings,
        role_configs=role_configs,
        permissions_catalog=PERMISSIONS_CATALOG,
    )


@app.route("/presse/artikel", methods=["POST"])
def presse_artikel_erstellen():
    if not is_press_logged_in():
        return redirect("/presse")
    if not has_press_access():
        flash("Kein Zugriff auf Presse-Artikel.", "danger")
        return redirect("/menu")

    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    if not title or not body:
        flash("Titel und Artikeltext sind erforderlich.", "danger")
        return redirect("/presse/bereich")

    image_filename = ""
    image_original_name = ""
    image_file = request.files.get("einsatz_image")
    if image_file and image_file.filename:
        if not allowed_file(image_file.filename):
            flash("Ungültiges Bildformat. Erlaubt: png, jpg, jpeg, gif.", "danger")
            return redirect("/presse/bereich")
        image_original_name = image_file.filename
        safe_name = secure_filename(image_file.filename)
        image_filename = f"press_{int(datetime.now(tz=timezone.utc).timestamp())}_{os.urandom(4).hex()}_{safe_name}"
        image_file.save(os.path.join(app.config["UPLOAD_FOLDER"], image_filename))

    server_id = current_server_id()
    articles = load_press_articles()
    article = {
        "id": str(int(datetime.now(tz=timezone.utc).timestamp() * 1000)),
        "server_id": server_id,
        "title": title,
        "body": body,
        "status": "pending",
        "author_role": get_press_role(),
        "author_name": session.get("presse_name", "Unbekannt"),
        "created_at": datetime.now().strftime("%d.%m.%Y %H:%M"),
        "approved_at": "",
        "approved_by": "",
        "image_filename": image_filename,
        "image_original_name": image_original_name,
    }
    articles.append(article)
    save_press_articles(articles)
    flash("Artikel gespeichert und zur Freigabe eingereicht.", "success")
    return redirect("/presse/bereich")


@app.route("/presse/artikel/<article_id>/freigeben", methods=["POST"])
def presse_artikel_freigeben(article_id):
    if not is_press_logged_in():
        return redirect("/presse")
    if not has_press_access():
        flash("Kein Zugriff auf Presse-Freigabe.", "danger")
        return redirect("/menu")
    if not has_permission("approve_articles"):
        flash("Deine Rolle darf Artikel nicht freigeben.", "danger")
        return redirect("/presse/bereich")

    server_id = current_server_id()
    articles = load_press_articles()
    article = next((a for a in articles if a.get("id") == article_id and a.get("server_id") == server_id), None)
    if not article:
        flash("Artikel nicht gefunden.", "danger")
        return redirect("/presse/bereich")
    if article.get("status") != "pending":
        flash("Artikel ist bereits freigegeben.", "warning")
        return redirect("/presse/bereich")

    webhooks = get_press_webhook_urls()
    if not webhooks:
        flash("Kein Presse-Webhook gesetzt.", "danger")
        return redirect("/presse/bereich")

    content = format_press_message(article)
    image_filename = (article.get("image_filename") or "").strip()
    image_path = os.path.join(app.config["UPLOAD_FOLDER"], image_filename) if image_filename else ""
    has_image = bool(image_filename and os.path.exists(image_path))
    ok_count = 0
    errors = []
    for idx, hook in enumerate(webhooks, start=1):
        try:
            if has_image:
                with open(image_path, "rb") as fh:
                    files = {"file": (image_filename, fh)}
                    resp = requests.post(hook, data={"content": content}, files=files, timeout=20)
            else:
                resp = requests.post(hook, data={"content": content}, timeout=12)
            if resp.status_code in (200, 204):
                ok_count += 1
            else:
                errors.append(f"Webhook {idx}: {resp.status_code}")
        except Exception as exc:
            errors.append(f"Webhook {idx}: {exc}")

    if ok_count > 0:
        article["status"] = "approved"
        article["approved_at"] = datetime.now().strftime("%d.%m.%Y %H:%M")
        article["approved_by"] = session.get("presse_name", "Leitung")
        save_press_articles(articles)
        msg = f"Artikel freigegeben und an {ok_count} Kanal/Kanäle gesendet."
        if image_filename and not has_image:
            msg += " Hinweis: Bilddatei war nicht mehr verfügbar."
        if errors:
            msg += " Fehler: " + ", ".join(errors)
        flash(msg, "success")
    else:
        flash("Freigabe fehlgeschlagen: " + ", ".join(errors), "danger")
    return redirect("/presse/bereich")


@app.route("/presse/logout", methods=["GET", "POST"])
def presse_logout():
    session.pop("presse_auth", None)
    session.pop("presse_role", None)
    session.pop("presse_name", None)
    session.pop("presse_username", None)
    session.pop("server_id", None)
    session.pop("server_code", None)
    session.pop("server_name", None)
    return redirect("/")


@app.route("/templates/presse_login.html", methods=["GET", "POST"])
def presse_login_template_alias():
    return presse_login()


@app.route("/templates/presse_bereich.html", methods=["GET"])
def presse_bereich_template_alias():
    return redirect("/presse/bereich")


@app.route("/templates/presse/logout", methods=["GET", "POST"])
def presse_logout_template_alias():
    return redirect("/presse/logout")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)


