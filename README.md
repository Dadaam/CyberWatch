# CyberWatch v3 — Veille Cybersécurité (FR/INTL)

Script Python multithreadé de **veille cybersécurité** qui collecte, catégorise et exporte en Markdown les articles publiés dans les **dernières 24 heures**.
Il s’appuie sur des **flux RSS** (France / International), un **scraper CERT-FR**, et l’**API NVD** (CVE récentes), avec nettoyage, déduplication et génération d’un rapport lisible.

---

## 🚀 Fonctionnalités clés

* **Collecte parallèle (ThreadPoolExecutor)** des flux RSS FR/INTL (jusqu’à 50 items/source).
* **Scraping** de la page des **alertes CERT-FR** récentes.
* **API NVD** pour les **CVE publiées** sur les dernières 24 h.
* **Nettoyage** (titres/descriptions), **catégorisation** par mots-clés, **suppression des doublons**.
* **Progress bar** en terminal + **bannière**.
* **Rapport Markdown** structuré, avec **sommaire**, sections **FRANCE** / **INTERNATIONAL**, **catégories** et **numérotation**.
* **Tri temporel** via un **cutoff 24 h** (tolérant aux formats de dates courants).
* **Résilient** (timeouts, exceptions capturées, fallback si dates manquantes).

---

## 📦 Prérequis

* **Python 3.9+** recommandé
* Dépendances Python :

  * `requests`
  * `feedparser`
  * `beautifulsoup4`
  * `python-dateutil`

### Installation rapide
```bash
# 1) Cloner votre repo / copier le script
# 2) Créer un venv (recommandé)
python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

# 3) Installer toutes les dépendances
pip install -r requirements.txt
```
> python-dateutil n’est pas strictement obligatoire mais **fortement recommandé** pour un parsing de dates plus fiable.


---

## 🧠 Structure & Logique

### Sources

* **FRANCE** : CERT-FR, ANSSI, CNIL, Zataz, Undernews, IT-Connect, Le Monde Informatique, JDN Sécurité…
* **INTERNATIONAL** : Krebs, BleepingComputer, SecurityWeek, The Hacker News, Dark Reading, Threatpost, SecureList, Mandiant, CrowdStrike, Microsoft, Google, Cisco Talos, SANS ISC, etc.
* **Web scraping** : page des **alertes CERT-FR**.
* **APIs** : **NVD** (CVE récentes, fenêtre 24 h).

### Catégories

* `VULNERABILITIES`
* `MALWARE & THREATS`
* `BREACHES & INCIDENTS`
* `TOOLS & TECHNIQUES`
* `CRITICAL ALERTS`
* `GENERAL NEWS` *(fourre-tout)*

La catégorisation repose sur la **présence de mots-clés** dans le titre/description.

### Déduplication

* **Par titre** (insensible à la casse, trimming).
* Un **article** est un dict normalisé : `title`, `link`, `source`, `date`, `description`.

---

## ▶️ Utilisation

Lancer le script directement :

```bash
python cyber_watch_v3.py
```

Comportement :

1. Affiche la bannière et la période (24 h glissantes).
2. Lance la **collecte parallèle** RSS avec **barre de progression**.
3. Récupère les **CVE** (NVD) et **alertes CERT-FR**.
4. **Déduplique** les résultats.
5. Affiche un **résumé terminal** (FR/INTL → catégories → 10 items max affichés par catégorie).
6. Génère un **Markdown** dans `rapports/` :
   `rapports/cyber_watch_YYYY-MM-DD_HH-MM-SS.md`

Exemple de fin d’exécution :

```
✅ Fichier généré: rapports/cyber_watch_2025-09-29_11-23-45.md
📍 Chemin complet: /…/rapports/cyber_watch_2025-09-29_11-23-45.md
🎉 Veille terminée avec succès!
```

---

## 📁 Format du rapport Markdown

* **Sommaire** avec le **nombre d’articles** par zone et par catégorie.
* Sections :

  * `🇫🇷 FRANÇAIS` → catégories → liste numérotée (titre + lien + source + description abrégée)
  * `🌍 ANGLAIS` → même structure
* **Footer** avec horodatage de génération.

---

## ⚙️ Configuration & Personnalisation

Vous pouvez modifier directement dans le code :

* **Fenêtre temporelle** : actuellement *24 h*
  → changez la ligne dans `__init__` :

  ```python
  self.time_limit = datetime.now() - timedelta(hours=24)
  ```
* **Limites par source** : RSS limité à **50 articles/source** (modifiable dans `fetch_single_rss_feed`).
* **Sources** : ajoutez/retirez des **flux RSS** dans `self.rss_sources['FRANCE']` / `['INTERNATIONAL']`.
* **Mots-clés** : adaptez `self.categories` pour améliorer la catégorisation.
* **Threads** : ajustez `max_workers` (par défaut **8**) dans `ThreadPoolExecutor`.

---

## ⏱️ Planification (cron/systemd/Task Scheduler)

### Linux/macOS — cron

```bash
crontab -e
# Tous les jours à 08:00
0 8 * * * /usr/bin/python3 /chemin/cyber_watch_v3.py >> /chemin/logs/cyberwatch.log 2>&1
```

### systemd (exemple)

* `~/.config/systemd/user/cyberwatch.service`
* `~/.config/systemd/user/cyberwatch.timer`

Activez avec :

```bash
systemctl --user enable --now cyberwatch.timer
```

### Windows — Planificateur de tâches

Créez une tâche qui exécute :

```
C:\Path\to\python.exe C:\Path\to\cyber_watch_v3.py
```

---

## 🌐 Réseau & Proxies

`requests` respecte généralement `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` :

```bash
export HTTPS_PROXY="http://proxy:port"
```

Timeouts HTTP déjà paramétrés (10–20 s) ; ajustables si besoin.

---

## 🔍 Dépannage

* **Peu de résultats / 1 seul article**

  * Vérifiez la **connectivité** réseau et les **proxies**.
  * Installez `python-dateutil` pour un parsing de dates plus solide.
  * Augmentez temporairement la fenêtre : `timedelta(hours=36)` ou `48`.
  * Certains flux (ex. Microsoft/Google blogs) publient **peu** sur 24 h.
* **Erreurs NVD**

  * L’endpoint est sollicité avec une fenêtre *hier → aujourd’hui*. Les serveurs NVD peuvent limiter/ralentir. Relancez plus tard si nécessaire.
* **Encodage Markdown**

  * Le fichier est écrit en **UTF-8**. Si rendu incorrect sous Windows, ouvrez avec un éditeur moderne (VS Code, Notepad++).

---

## 🧪 Bonnes pratiques

* **Évitez** d’augmenter trop `max_workers` pour ne pas **sur-solliciter** les sites.
* **Limitez** à ~50 items/source pour garder un rapport digeste.
* **Élargissez** progressivement les mots-clés pour réduire les faux positifs.
* **Ajoutez** des sources sectorielles (santé, finance, OT/ICS) selon vos besoins.

---

## 🔒 Mentions légales & éthique

* Respectez les **CGU** des sites sources (taux de requêtes raisonnable).
* Les contenus appartiennent à leurs **ayants droit** ; ce script **agrège** et **pointe** vers les articles originaux.
* Usage interne recommandé (veille, sensibilisation). Pour diffusion publique, demandez les **autorisations** nécessaires.

---

## 🗺️ Roadmap (idées d’amélioration)

* Export **CSV/JSON** en plus du Markdown.
* **Score de priorité** (pondérer CVSS, mots-clés, sources).
* Détection d’**exploitation active** (heuristiques enrichies).
* **Enrichissement CVE** (CVSS, vendors, CPE).
* **Sortie HTML** stylée / page web statique.
* Intégration **Slack/Teams/Discord** (webhooks).
* **Tests unitaires** (date parsing, dédup, catégorisation).

---

## 🧾 Licence

Ce projet est sous licence MIT. Veuillez vous reférer au fichier LICENCE pour plus de détails.

---

## 🙋 Support

Ouvrez une issue (ou envoyez les logs d’exécution) avec :

* OS / version Python
* Liste des paquets installés (`pip freeze`)
* Extrait d’erreurs et **compteur d’articles** affiché après la collecte RSS.

Bon run. ✅
