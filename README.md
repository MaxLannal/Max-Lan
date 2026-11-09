# Max-Lan
Personal Website

The site of Max (Jinghan) Lan: a scroll-driven launch scene with a qubit field, then
Projects (CollegeDeck, Archstone, Quarterly), Blogs, Resume and Contact.

Live at **https://maxlannal.github.io/Max-Lan/**. Every push to `main` republishes `public/`
(see `.github/workflows/pages.yml`).

## Run it locally

```bash
python3 server.py
```

Then open http://127.0.0.1:8123. The page itself is `public/index.html`; pictures are in `public/images/`.

## Edit text on the page

Type `edit` anywhere on the page (or open `/#admin`) and sign in with the admin password.
Click any text to change it, add project links under each project, then **Save to site**.
Saving rewrites `public/index.html` and keeps the previous version in `backups/`.

The first run creates an admin password and prints it once. Change it any time:

```bash
python3 server.py --set-password
```

`admin.json` (the password hash) and `backups/` are listed in `.gitignore` and never committed.

Editing and saving only work on this local server. On the published site, push your saved
changes instead:

```bash
git add -A && git commit -m "Update site" && git push
```
