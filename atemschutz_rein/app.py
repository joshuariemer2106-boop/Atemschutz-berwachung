from flask import Flask, render_template, request
import os
import requests
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

load_dotenv()

WEBHOOK_URL_1 = (os.getenv("DISCORD_WEBHOOK_URL") or "").strip()
WEBHOOK_URL_2 = (os.getenv("DISCORD_WEBHOOK_URL_2") or "").strip()

BASE_DIR = os.path.dirname(__file__)
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def get_webhook_urls():
    return [url for url in [WEBHOOK_URL_1, WEBHOOK_URL_2] if url]


@app.route("/", methods=["GET"])
def start():
    return render_template("index.html", user_name="Atemschutz")


@app.route("/atemschutz", methods=["POST"])
def atemschutz_submit():
    screenshot = request.files.get("screenshot")
    if not screenshot or not screenshot.filename:
        return ("Screenshot fehlt.", 400)

    filename = secure_filename("screenshot.png")
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    screenshot.save(path)

    webhooks = get_webhook_urls()
    if not webhooks:
        return ("Kein Discord Webhook gesetzt.", 500)

    sent = 0
    for hook in webhooks:
        try:
            with open(path, "rb") as fh:
                files = {"file": (filename, fh, "image/png")}
                resp = requests.post(hook, files=files, timeout=20)
            if resp.status_code in (200, 204):
                sent += 1
        except Exception:
            pass

    if sent == 0:
        return ("Senden fehlgeschlagen.", 502)
    return ("OK", 200)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5050)), debug=True)
