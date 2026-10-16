# Mailbord offline

Leesapp voor het Mailbord die ook zonder internet werkt. Zet 'm op je beginscherm via het menu van je browser ("Toevoegen aan startscherm").

- `index.html`, `app.js`, `sw.js`: de app. De service worker bewaart app en data op het toestel.
- `data/`: de mail, **versleuteld** (AES-256-GCM). Zonder sleutel onleesbaar.
- `data/keys.json`: de datasleutel, per gekoppeld toestel versleuteld met de publieke sleutel van dat toestel. De privésleutel blijft op het toestel.
- `tools/export.py`: zet het Mailbord om naar `data/`. Draait elk uur via Claude.
- `tools/devices.json`: publieke sleutels van gekoppelde toestellen.

Een toestel koppelen: open de app, kopieer de koppelcode en stuur die naar Claude.
