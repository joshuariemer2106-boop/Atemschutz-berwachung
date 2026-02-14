from flask import Flask, render_template, request, redirect, flash, url_for
import os
import requests
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import re

load_dotenv()
WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

BASE_DIR = os.path.dirname(__file__)
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif"}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = os.getenv("FLASK_SECRET", "dev-secret")


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # check if it's a screenshot upload
        screenshot = request.files.get('screenshot')
        if screenshot and screenshot.filename:
            # This is an auto-screenshot from browser
            try:
                filename = secure_filename(f"screenshot_{os.urandom(4).hex()}.png")
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                screenshot.save(filepath)
                
                if WEBHOOK_URL:
                    with open(filepath, 'rb') as fh:
                        files = {'file': (filename, fh, 'image/png')}
                        resp = requests.post(WEBHOOK_URL, files=files, timeout=20)
                    
                    if resp.status_code in (200, 204):
                        return {'status': 'success', 'message': 'Screenshot erfolgreich gesendet'}, 200
                    else:
                        return {'status': 'error', 'message': f'Webhook Error: {resp.status_code}'}, 500
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

        if WEBHOOK_URL:
            data = {"content": content}
            files = None
            if saved_path:
                files = {"file": (filename, open(saved_path, "rb"), file.mimetype)}
            try:
                resp = requests.post(WEBHOOK_URL, data=data, files=files, timeout=10)
                if resp.status_code in (200, 204):
                    flash("Eintrag erfolgreich gesendet.", "success")
                else:
                    flash(f"Webhook-Fehler: {resp.status_code}", "danger")
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

        return redirect(url_for("index"))

    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
