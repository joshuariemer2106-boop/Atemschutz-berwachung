# Atemschutz (Rein)

Standalone-Version nur fuer Atemschutz.

## Start

```powershell
cd d:\Atemschutzüberwachung\atemschutz_rein
pip install -r requirements.txt
python app.py
```

Dann im Browser aufrufen:

- `http://127.0.0.1:5050/`

## Hinweise

- Die App sendet Screenshots an `DISCORD_WEBHOOK_URL` und optional `DISCORD_WEBHOOK_URL_2`.
- Webhooks koennen in einer `.env` im Projekt oder systemweit gesetzt werden.
