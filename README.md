# Cyber Watch v3.0 - Veille Cybersécurité Quotidienne

Script Python automatisé pour la collecte et l'organisation des actualités cybersécurité des **dernières 24 heures**.

## ✨ Fonctionnalités

- **🚀 Traitement parallèle** - Collecte simultanée depuis 25+ sources RSS
- **📊 Catégorisation automatique** - Classification intelligente par mots-clés
- **🧹 Déduplication** - Suppression automatique des doublons
- **📝 Markdown natif** - Sortie propre sans HTML pour une lecture optimale
- **⏰ Monitoring quotidien** - Conçu pour un usage journalier (24h strictes)
- **🔄 APIs intégrées** - CVE NVD, CERT-FR, alertes CISA

## � Sources RSS (25 sources)

### Sources principales
- **Krebs on Security** - Investigations et analyses approfondies
- **BleepingComputer** - Actualités techniques et incidents
- **The Hacker News** - News rapides et tendances
- **SecurityWeek** - Actualités entreprise et industrie
- **Dark Reading** - Analyses stratégiques cybersécurité

### Sources spécialisées
- **CISA** - Alertes gouvernementales US
- **SANS ISC** - Centre d'analyse des incidents
- **Mandiant/FireEye** - Threat intelligence
- **CrowdStrike** - Recherche sur les menaces
- **Kaspersky SecureList** - Analyses malware

### Sources médias tech
- **InfoSecurity Magazine** - News secteur cyber
- **SC Magazine** - Actualités solutions sécurité
- **ZDNet Security** - Tech et sécurité
- **Ars Technica** - Analyses techniques détaillées

## 🏷️ Catégories

- **VULNERABILITIES** - CVE, exploits, correctifs, failles zero-day
- **MALWARE & THREATS** - Ransomware, trojans, campagnes APT
- **BREACHES & INCIDENTS** - Fuites de données, cyberattaques
- **TOOLS & TECHNIQUES** - Outils, frameworks, méthodologies
- **CRITICAL ALERTS** - Alertes urgentes, exploitation active
- **GENERAL NEWS** - Actualités, réglementation, études

## ⚡ Installation

### Prérequis
- **Python 3.8+**
- **Connexion internet** pour accéder aux flux RSS

### Dépendances
```bash
pip install requests feedparser beautifulsoup4 python-dateutil
```

### Installation rapide
```bash
# Cloner le dépôt
git clone https://github.com/votre-repo/cyber-watch.git
cd cyber-watch

# Installer les dépendances
pip install -r requirements.txt

# Lancer la veille
python cyber_watch.py
```

### Environnement virtuel (recommandé)
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

pip install -r requirements.txt
```

## 🎯 Utilisation

### Lancement quotidien
```bash
python cyber_watch.py
```

### Sortie console
```
   _____      _                             _       _            ____  
  / ____|    | |                           | |     | |          |___ \ 
 | |    _   _| |__   ___ _ ____      ____ _| |_ ___| |__   __   ____) |
 | |   | | | | '_ \ / _ \ '__\ \ /\ / / _` | __/ __| '_ \  \ \ / /__ < 
 | |___| |_| | |_) |  __/ |   \ V  V / (_| | || (__| | | |  \ V /___) |
  \_____\__, |_.__/ \___|_|    \_/\_/ \__,_|\__\___|_| |_|   \_/|____/ 
         __/ |                                                         
        |___/                                                          

� Démarrage de la veille cybersécurité...
⏰ Période: dernières 24h (depuis 28/09/2025 13:53)

🔍 Récupération des flux RSS en parallèle...
📡 [████████████████████████████████████████] 100.0% 
✅ 31 articles récupérés depuis 24 sources

� RÉSULTATS DE LA VEILLE CYBERSÉCURITÉ
�📈 Total: 31 articles trouvés

🔹 VULNERABILITIES
• SonicWall SSL VPN Attacks Escalate, Bypassing MFA
• Akira Ransomware's Exploitation of SonicWall Vulnerability Continues
...

💾 Génération du fichier markdown...
✅ Fichier généré: cyber_watch_20250929_135335.md
```

### Sortie Markdown
Le script génère automatiquement un fichier `.md` avec un format propre :

```markdown
# Veille Cybersécurité - 29/09/2025 13:53

## Sommaire
- **VULNERABILITIES**: 7 articles
- **MALWARE & THREATS**: 8 articles  
- **BREACHES & INCIDENTS**: 2 articles
- **TOOLS & TECHNIQUES**: 1 articles
- **GENERAL NEWS**: 13 articles

**Total**: 31 articles

## VULNERABILITIES

1. **[SonicWall SSL VPN Attacks Escalate, Bypassing MFA](https://www.infosecurity-magazine.com/news/sonicwall-ssl-vpn-attacks-escalate/)**
   - Source: *InfoSecurity Magazine*
   - Description: Akira ransomware group continues to exploit SonicWall vulnerabilities...

2. **[CVE-2025-XXXX: Critical RCE in Popular Framework](https://example.com/cve)**
   - Source: *SecurityWeek*
   - Description: Remote code execution vulnerability affects millions...
```

## ⚙️ Configuration

### Ajouter des sources RSS
Modifiez directement `cyber_watch.py` dans la section `rss_sources` :

```python
self.rss_sources = {
    'Votre Source': 'https://example.com/rss',
    'Autre Source': 'https://autre-site.com/feed',
    # ... sources existantes
}
```

### Personnaliser les catégories
Ajustez les mots-clés de classification dans `categories` :

```python
self.categories = {
    'MA_CATEGORIE': [
        'mot-clé1', 'mot-clé2', 'expression-clé'
    ],
    # ... catégories existantes
}
```

### Paramètres du script
```python
# Période fixe (24h pour usage quotidien)
self.time_limit = datetime.now() - timedelta(hours=24)

# Nombre d'articles par source (optimisé)
for entry in feed.entries[:50]:  # 50 articles max par source

# Threads parallèles
with ThreadPoolExecutor(max_workers=8) as executor:
```

## 📝 Fichiers générés

### Sauvegarde automatique
- **Format** : `cyber_watch_YYYYMMDD_HHMMSS.md`
- **Emplacement** : Répertoire d'exécution
- **Contenu** : Markdown natif, lisible et structuré
- **Encodage** : UTF-8 avec support complet des caractères

### Structure du fichier
```
cyber_watch_20250929_135335.md
├── En-tête avec date/heure
├── Sommaire par catégorie  
├── Articles par catégorie
│   ├── Titre (lien clickable)
│   ├── Source
│   └── Description nettoyée
└── Footer avec métadonnées
```

## 🤖 Automatisation quotidienne

### Cron (Linux/Mac)
```bash
# Veille tous les jours à 9h00
0 9 * * * cd /path/to/cyber-watch && python3 cyber_watch.py

# Avec logging
0 9 * * * cd /path/to/cyber-watch && python3 cyber_watch.py >> logs/cyber_watch_$(date +\%Y\%m\%d).log 2>&1
```

### Planificateur de tâches Windows
```powershell
# Créer une tâche quotidienne
schtasks /create /tn "Cyber Watch Daily" /tr "python C:\path\to\cyber_watch.py" /sc daily /st 09:00

# Ou via interface graphique :
# 1. Planificateur de tâches → Créer une tâche de base
# 2. Déclencheur : Quotidien à 09:00
# 3. Action : python.exe
# 4. Argument : C:\path\to\cyber_watch.py
```

### Docker (optionnel)
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY cyber_watch.py .
CMD ["python", "cyber_watch.py"]
```

### Script d'automatisation
```bash
#!/bin/bash
# cyber_watch_daily.sh
DATE=$(date +%Y%m%d)
cd /path/to/cyber-watch

echo "[$DATE] Début de la veille cybersécurité"
python3 cyber_watch.py

# Archiver les anciens fichiers (garde 7 jours)
find . -name "cyber_watch_*.md" -mtime +7 -delete

echo "[$DATE] Veille terminée"
```

## 🚨 Robustesse et fiabilité

### Gestion d'erreurs intégrée
- **Sources indisponibles** : Ignorées automatiquement, pas d'interruption
- **Timeouts** : Gestion automatique des sources lentes
- **Formats de date variés** : Parsing robuste avec `dateutil` + fallback
- **Contenu malformé** : Nettoyage HTML et validation des données
- **Traitement parallèle** : Une source en erreur n'affecte pas les autres

### Mécanismes de récupération
```python
# Parsing de date intelligent
try:
    article_date = date_parser.parse(date_str)  # dateutil (flexible)
except:
    # Fallback vers formats manuels
    for fmt in formats:
        try:
            article_date = datetime.strptime(date_str, fmt)
        except:
            continue
```

## 🔒 Bonnes pratiques

### Éthique et respect
- **User-Agent identifié** : Requêtes transparentes
- **Pas de scraping agressif** : Utilisation des flux RSS officiels
- **Sources publiques uniquement** : Respect de la propriété intellectuelle  
- **Rate limiting implicite** : Traitement parallèle respectueux

### Performance
- **ThreadPoolExecutor** : 8 workers pour traitement parallèle optimal
- **Session HTTP réutilisée** : Optimisation des connexions
- **Limitation intelligente** : 50 articles max par source (équilibré)

## 🐛 Dépannage

### Problèmes courants

**Pas d'articles récupérés**
```bash
# Vérifier la connexion internet
curl https://krebsonsecurity.com/feed/

# Tester une source individuellement
python -c "import feedparser; print(len(feedparser.parse('https://krebsonsecurity.com/feed/').entries))"
```

**Erreurs SSL/certificats**
```bash
pip install --upgrade certifi requests
# Ou sur Windows :
pip install --trusted-host pypi.org --trusted-host pypi.python.org --upgrade certifi
```

**Dépendance manquante `dateutil`**
```bash
pip install python-dateutil
```

**Problèmes d'encodage (Windows)**
```powershell
# Définir l'encodage UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001
```

### Debug et logs
```python
# Ajouter des prints de debug dans le code
def fetch_single_rss_feed(self, source_name, rss_url):
    print(f"Fetching {source_name}...")  # Debug
    try:
        feed = feedparser.parse(rss_url)
        print(f"  Found {len(feed.entries)} entries")  # Debug
```

## 🚀 Fonctionnalités avancées

### Performances
- **⚡ Traitement parallèle** : ThreadPoolExecutor avec 8 workers
- **📈 Optimisé pour le volume** : 50 articles/source × 25 sources = 1250+ articles potentiels
- **🧹 Déduplication intelligente** : Suppression automatique des doublons
- **📅 Filtrage temporel précis** : Strictement les dernières 24h

### Qualité des données
- **🔍 Nettoyage HTML complet** : Suppression tags + entités HTML
- **📝 Markdown natif pur** : Pas de HTML dans la sortie
- **🏷️ Catégorisation automatique** : Classification par mots-clés intelligents
- **🔗 Liens préservés** : URLs clickables dans le markdown

## 📊 Statistiques typiques

```
Sources actives    : 25 flux RSS
Articles collectés : 30-100+ par jour
Temps d'exécution  : 15-30 secondes
Taille fichier MD  : 10-50 KB
Catégories         : 6 classifications
```

### Ajouter une source RSS
```python
# 1. Tester le flux
import feedparser
feed = feedparser.parse('https://nouveau-site.com/rss')
print(f"Entries: {len(feed.entries)}")

# 2. Ajouter dans rss_sources
'Nouveau Site': 'https://nouveau-site.com/rss',
```

### Améliorer la catégorisation
```python
# Ajouter des mots-clés dans categories
'VOTRE_CATEGORIE': [
    'nouveau-mot-clé', 'expression spécifique'
]
```

## 📄 Licence

**MIT License** - Utilisation libre pour projets personnels et commerciaux.

## 🎯 Cas d'usage

- **🏢 Veille entreprise** : Monitoring quotidien des menaces
- **🎓 Formation cybersécurité** : Ressources pédagogiques à jour  
- **📰 Curation de contenu** : Base pour newsletters/rapports
- **🔍 Intelligence threat** : Suivi des tendances et incidents
- **📱 Alertes automatisées** : Intégration dans workflows d'équipe

---

**Cyber Watch v3.0** - *Veille cybersécurité moderne, rapide et fiable*
