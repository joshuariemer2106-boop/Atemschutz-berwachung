# FiveM Tablet Resource

## Installation
1. Kopiere den Ordner `fivem_tablet` in deinen FiveM Ressourcen-Ordner.
2. Passe in `config.lua` die URL an:
   - `Config.TabletUrl = "https://DEINE-APP.onrender.com/presse"`
3. Trage die Resource in deiner `server.cfg` ein:
   - `ensure fivem_tablet`
4. Server neu starten.

## Nutzung
- Taste `F2` (oder Command `/tablet`) öffnet/schließt das Tablet.
- Im Tablet wird deine Web-App geladen.

## Hinweise
- Verwende eine **HTTPS**-URL (kein HTTP).
- Falls du ein Framework nutzt (ESX/QBCore), funktioniert diese Resource trotzdem standalone.
