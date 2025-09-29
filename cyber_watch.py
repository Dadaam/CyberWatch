#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import feedparser
from datetime import datetime, timedelta
import re
import json
from bs4 import BeautifulSoup
import time
import sys
from urllib.parse import urljoin, urlparse
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class CyberWatchV3:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Sources RSS par zone géographique
        self.rss_sources = {
            'FRANCE': {
                'CERT-FR': 'https://www.cert.ssi.gouv.fr/feed/',
                'ANSSI': 'https://www.ssi.gouv.fr/feed/',
                'CNIL': 'https://www.cnil.fr/fr/rss.xml',
                'Zataz': 'https://www.zataz.com/feed/',
                'Undernews': 'https://www.undernews.fr/feed/',
                'IT-Connect': 'https://www.it-connect.fr/feed/',
                'Le Monde Informatique': 'https://www.lemondeinformatique.fr/flux-rss/securite.xml',
                'Journal du Net Sécurité': 'https://www.journaldunet.com/rss/securite.xml',
            },
            'INTERNATIONAL': {
                'Krebs on Security': 'https://krebsonsecurity.com/feed/',
                'BleepingComputer': 'https://www.bleepingcomputer.com/feed/',
                'SecurityWeek': 'https://www.securityweek.com/feed',
                'The Hacker News': 'https://thehackernews.com/feeds/posts/default',
                'Dark Reading': 'https://www.darkreading.com/rss/all.xml',
                'Threatpost': 'https://threatpost.com/feed/',
                'Security Affairs': 'https://securityaffairs.co/wordpress/feed',
                'CISA': 'https://www.cisa.gov/news.xml',
                'SANS ISC': 'https://isc.sans.edu/rssfeed.xml',
                'InfoSecurity Magazine': 'https://www.infosecurity-magazine.com/rss/news/',
                'SC Magazine': 'https://www.scmagazine.com/home/feed/',
                'Ars Technica Security': 'https://feeds.arstechnica.com/arstechnica/security',
                'Naked Security': 'https://nakedsecurity.sophos.com/feed/',
                'Malwarebytes Labs': 'https://blog.malwarebytes.com/feed/',
                'Kaspersky SecureList': 'https://securelist.com/feed/',
                'Mandiant': 'https://www.mandiant.com/resources/blog/rss.xml',
                'CrowdStrike': 'https://www.crowdstrike.com/blog/feed/',
                'Microsoft Security': 'https://www.microsoft.com/security/blog/feed/',
                'Google Security': 'https://security.googleblog.com/feeds/posts/default',
                'Cisco Talos': 'https://blog.talosintelligence.com/feeds/posts/default',
            }
        }
        
        # Sources web à scraper
        self.web_sources = {
            'CERT-FR': 'https://www.cert.ssi.gouv.fr/',
            'US-CERT': 'https://us-cert.cisa.gov/ncas/alerts',
            'CVE Details': 'https://www.cvedetails.com/vulnerability-feeds.php',
        }
        
        # APIs publiques
        self.apis = {
            'nvd_cve': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'mitre_cve': 'https://cve.mitre.org/data/downloads/allitems-cvrf.xml'
        }
        
        # Catégories et mots-clés
        self.categories = {
            'VULNERABILITIES': [
                'vulnerability', 'cve', 'exploit', 'patch', 'zero-day', 'rce', 'sql injection',
                'xss', 'buffer overflow', 'privilege escalation', 'remote code execution',
                'security flaw', 'security hole', 'backdoor', 'bypass'
            ],
            'MALWARE & THREATS': [
                'malware', 'ransomware', 'trojan', 'virus', 'worm', 'spyware', 'adware',
                'rootkit', 'botnet', 'rat', 'stealer', 'loader', 'cryptojacker',
                'banking trojan', 'apt', 'threat actor'
            ],
            'BREACHES & INCIDENTS': [
                'data breach', 'hack', 'attack', 'incident', 'compromised', 'stolen data',
                'leaked', 'cyberattack', 'security incident', 'breach', 'hacked',
                'unauthorized access', 'data leak', 'security breach'
            ],
            'TOOLS & TECHNIQUES': [
                'tool', 'technique', 'framework', 'methodology', 'pentest', 'red team',
                'blue team', 'forensics', 'incident response', 'security tool',
                'analysis', 'research', 'proof of concept', 'poc'
            ],
            'CRITICAL ALERTS': [
                'critical', 'urgent', 'emergency', 'immediate', 'high risk', 'severe',
                'widespread', 'active exploitation', 'in the wild', 'alert'
            ],
            'GENERAL NEWS': []  # Catch-all pour les autres articles
        }
        
        # Structure des articles par zone géographique et catégorie
        self.articles = {
            'FRANCE': {cat: [] for cat in self.categories.keys()},
            'INTERNATIONAL': {cat: [] for cat in self.categories.keys()}
        }
        
        # Date limite (24h)
        self.time_limit = datetime.now() - timedelta(hours=24)

    def print_banner(self):
        """Affiche une belle bannière"""
        banner = """
   _____      _                             _       _            ____  
  / ____|    | |                           | |     | |          |___ \ 
 | |    _   _| |__   ___ _ ____      ____ _| |_ ___| |__   __   ____) |
 | |   | | | | '_ \ / _ \ '__\ \ /\ / / _` | __/ __| '_ \  \ \ / /__ < 
 | |___| |_| | |_) |  __/ |   \ V  V / (_| | || (__| | | |  \ V /___) |
  \_____\__, |_.__/ \___|_|    \_/\_/ \__,_|\__\___|_| |_|   \_/|____/ 
         __/ |                                                         
        |___/                                                          
"""
        print(banner)

    def print_progress(self, current, total, source_name=""):
        """Affiche une barre de progression"""
        percent = (current / total) * 100
        bar_length = 40
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        print(f'\r📡 [{bar}] {percent:.1f}% - {source_name[:30]:<30}', end='', flush=True)

    def is_recent(self, date_str):
        """Vérifie si un article est récent (moins de 24h) avec formats de date étendus"""
        if not date_str:
            return True  # Si pas de date, on inclut l'article
            
        try:
            # Import dateutil pour un parsing plus robuste
            from dateutil import parser as date_parser
            
            # Nettoie la chaîne de date
            date_str = str(date_str).strip()
            
            # Formats courants de RSS/Atom
            formats = [
                '%a, %d %b %Y %H:%M:%S %z',       # RFC 2822
                '%a, %d %b %Y %H:%M:%S %Z',       # RFC 2822 avec timezone
                '%Y-%m-%dT%H:%M:%S%z',            # ISO 8601 avec timezone
                '%Y-%m-%dT%H:%M:%SZ',             # ISO 8601 UTC
                '%Y-%m-%dT%H:%M:%S.%f%z',         # ISO 8601 avec microsecondes
                '%Y-%m-%dT%H:%M:%S.%fZ',          # ISO 8601 UTC avec microsecondes
                '%Y-%m-%d %H:%M:%S',              # Format simple
                '%Y-%m-%d',                       # Date seule
                '%d %b %Y %H:%M:%S',              # Format alternatif
                '%d/%m/%Y %H:%M:%S',              # Format français
                '%m/%d/%Y %H:%M:%S',              # Format américain
            ]
            
            article_date = None
            
            # Essaie d'abord avec dateutil (plus flexible)
            try:
                article_date = date_parser.parse(date_str)
            except:
                # Si dateutil échoue, essaie les formats manuels
                for fmt in formats:
                    try:
                        article_date = datetime.strptime(date_str, fmt)
                        break
                    except:
                        continue
            
            if article_date:
                # Normalise la timezone
                if article_date.tzinfo is not None:
                    article_date = article_date.replace(tzinfo=None)
                
                return article_date >= self.time_limit
            
            return True  # Si parsing impossible, on inclut l'article
            
        except ImportError:
            # Fallback si dateutil n'est pas installé
            try:
                for fmt in ['%a, %d %b %Y %H:%M:%S %z', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S']:
                    try:
                        article_date = datetime.strptime(str(date_str), fmt)
                        if article_date.tzinfo is not None:
                            article_date = article_date.replace(tzinfo=None)
                        return article_date >= self.time_limit
                    except:
                        continue
                return True
            except:
                return True

    def categorize_article(self, title, description=""):
        """Catégorise un article selon son titre et sa description"""
        content = (title + " " + description).lower()
        
        for category, keywords in self.categories.items():
            if category == 'GENERAL NEWS':
                continue
            
            for keyword in keywords:
                if keyword.lower() in content:
                    return category
        
        return 'GENERAL NEWS'

    def clean_title(self, title):
        """Nettoie le titre des articles"""
        # Supprime les tags HTML
        title = re.sub(r'<[^>]+>', '', title)
        # Supprime les caractères spéciaux en excès
        title = re.sub(r'\s+', ' ', title).strip()
        # Limite la longueur
        if len(title) > 100:
            title = title[:97] + "..."
        return title

    def clean_description(self, description):
        """Nettoie la description des articles - supprime tout HTML"""
        if not description:
            return ""
        
        # Supprime tous les tags HTML
        description = re.sub(r'<[^>]+>', '', description)
        # Décode les entités HTML
        description = re.sub(r'&nbsp;', ' ', description)
        description = re.sub(r'&amp;', '&', description)
        description = re.sub(r'&lt;', '<', description)
        description = re.sub(r'&gt;', '>', description)
        description = re.sub(r'&quot;', '"', description)
        description = re.sub(r'&#039;', "'", description)
        # Supprime les espaces multiples et nettoie
        description = re.sub(r'\s+', ' ', description).strip()
        
        return description

    def fetch_single_rss_feed(self, source_name, rss_url, zone):
        """Récupère un seul flux RSS pour une zone géographique donnée"""
        articles = {cat: [] for cat in self.categories.keys()}
        
        try:
            feed = feedparser.parse(rss_url)
            
            for entry in feed.entries[:50]:  # Limite à 50 articles par source pour plus de contenu
                # Vérification de la date
                pub_date = getattr(entry, 'published', getattr(entry, 'updated', ''))
                
                if not self.is_recent(pub_date):
                    continue
                
                title = self.clean_title(entry.title)
                link = entry.link
                raw_description = getattr(entry, 'summary', getattr(entry, 'description', ''))
                description = self.clean_description(raw_description)
                
                # Catégorisation
                category = self.categorize_article(title, description)
                
                article = {
                    'title': title,
                    'link': link,
                    'source': source_name,
                    'date': pub_date,
                    'description': description[:200] if description else ''
                }
                
                articles[category].append(article)
                
        except Exception as e:
            pass
            
        return source_name, articles, zone

    def fetch_rss_feeds(self):
        """Récupère les flux RSS en parallèle pour de meilleures performances"""
        print("🔍 Recherche d'articles...")
        
        # Calcul du nombre total de sources
        total_sources = sum(len(sources) for sources in self.rss_sources.values())
        completed = 0
        
        # Thread lock pour la synchronisation
        lock = threading.Lock()
        
        def update_progress(source_name):
            nonlocal completed
            with lock:
                completed += 1
                self.print_progress(completed, total_sources, source_name)
        
        # Utilise ThreadPoolExecutor pour le traitement parallèle
        with ThreadPoolExecutor(max_workers=8) as executor:
            # Soumet toutes les tâches pour chaque zone
            future_to_info = {}
            
            for zone, sources in self.rss_sources.items():
                for source_name, rss_url in sources.items():
                    future = executor.submit(self.fetch_single_rss_feed, source_name, rss_url, zone)
                    future_to_info[future] = (source_name, zone)
            
            # Traite les résultats au fur et à mesure
            for future in as_completed(future_to_info):
                source_name, zone = future_to_info[future]
                update_progress(source_name)
                
                try:
                    _, articles, returned_zone = future.result()
                    
                    # Fusionne les articles dans les catégories par zone
                    with lock:
                        for category, article_list in articles.items():
                            self.articles[zone][category].extend(article_list)
                            
                except Exception as e:
                    pass
        
        print()  # Nouvelle ligne après la barre de progression
        
        # Affiche le nombre d'articles récupérés
        total_articles = 0
        for zone_articles in self.articles.values():
            for category_articles in zone_articles.values():
                total_articles += len(category_articles)
        
        print(f"✅ {total_articles} articles récupérés depuis {total_sources} sources")

    def fetch_cve_data(self):
        """Récupère les CVE récentes"""
        print("🔍 Récupération des CVE récentes...")
        
        try:
            # Date d'aujourd'hui pour l'API NVD
            today = datetime.now().strftime('%Y-%m-%d')
            yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
            
            url = f"{self.apis['nvd_cve']}?pubStartDate={yesterday}&pubEndDate={today}"
            
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                for vuln in data.get('vulnerabilities', [])[:15]:  # Limite à 15 CVE
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id', '')
                    descriptions = cve.get('descriptions', [])
                    description = descriptions[0].get('value', '') if descriptions else ''
                    
                    title = f"CVE {cve_id}: {description[:80]}..." if len(description) > 80 else f"CVE {cve_id}: {description}"
                    link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    
                    article = {
                        'title': title,
                        'link': link,
                        'source': 'NVD',
                        'date': datetime.now().isoformat(),
                        'description': description[:200]
                    }
                    
                    self.articles['INTERNATIONAL']['VULNERABILITIES'].append(article)
                    
        except Exception as e:
            print(f"⚠️  Erreur CVE: {str(e)}")

    def scrape_cert_fr(self):
        """Scrape les alertes CERT-FR"""
        print("🇫🇷 Récupération des alertes CERT-FR...")
        
        try:
            url = "https://www.cert.ssi.gouv.fr/alerte/"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Recherche des alertes récentes
                alerts = soup.find_all('div', class_='alert-item')[:10]
                
                for alert in alerts:
                    try:
                        title_elem = alert.find('h3') or alert.find('a')
                        if title_elem:
                            title = self.clean_title(title_elem.get_text())
                            link_elem = alert.find('a')
                            link = urljoin(url, link_elem['href']) if link_elem and 'href' in link_elem.attrs else url
                            
                            article = {
                                'title': f"CERT-FR: {title}",
                                'link': link,
                                'source': 'CERT-FR',
                                'date': datetime.now().isoformat(),
                                'description': 'Alerte de sécurité CERT-FR'
                            }
                            
                            category = self.categorize_article(title)
                            self.articles['FRANCE'][category].append(article)
                            
                    except:
                        continue
                        
        except Exception as e:
            print(f"⚠️  Erreur CERT-FR: {str(e)}")

    def remove_duplicates(self):
        """Supprime les doublons par zone et catégorie"""
        for zone in self.articles:
            for category in self.articles[zone]:
                seen_titles = set()
                unique_articles = []
                
                for article in self.articles[zone][category]:
                    title_key = article['title'].lower().strip()
                    if title_key not in seen_titles:
                        seen_titles.add(title_key)
                        unique_articles.append(article)
                
                self.articles[zone][category] = unique_articles

    def generate_terminal_output(self):
        """Génère la sortie pour le terminal selon le format FRANCE/INTERNATIONAL"""
        print("\n" + "="*80)
        print("📊 RÉSULTATS DE LA VEILLE CYBERSÉCURITÉ")
        print("="*80)
        
        # Calcul du total
        total_articles = 0
        for zone_articles in self.articles.values():
            for category_articles in zone_articles.values():
                total_articles += len(category_articles)
        
        print(f"📈 Total: {total_articles} articles trouvés\n")
        
        # Affichage par zone géographique
        for zone in ['FRANCE', 'INTERNATIONAL']:
            zone_total = sum(len(articles) for articles in self.articles[zone].values())
            if zone_total > 0:
                flag = "🇫🇷" if zone == "FRANCE" else "🌍"
                display_name = "FRANÇAIS" if zone == "FRANCE" else "ANGLAIS"
                print(f"\n{flag} === {display_name} === ({zone_total} articles)")
                print("="*60)
                
                for category, articles in self.articles[zone].items():
                    if articles:
                        print(f"\n🔹 {category}")
                        print("-" * 50)
                        
                        for article in articles[:10]:  # Limite à 10 par catégorie pour l'affichage
                            title = article['title'][:70] + "..." if len(article['title']) > 70 else article['title']
                            print(f"  • {title}")
                            print(f"    🔗 {article['link']}")
                            print(f"    📰 Source: {article['source']}\n")

    def generate_markdown_file(self):
        """Génère le fichier markdown selon le format FRANCE/INTERNATIONAL"""
        # Créer le dossier rapports s'il n'existe pas
        reports_dir = "rapports"
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
        
        # Format chronologique optimal : YYYY-MM-DD_HH-MM-SS pour tri automatique
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filename = f"{reports_dir}/cyber_watch_{timestamp}.md"
        
        with open(filename, 'w', encoding='utf-8') as f:
            # En-tête
            f.write(f"# Veille Cybersécurité - {datetime.now().strftime('%d/%m/%Y %H:%M')}\n\n")
            f.write("*Rapport automatisé des dernières 24 heures*\n\n")
            
            # Sommaire global
            f.write("## Sommaire\n\n")
            
            total_global = 0
            for zone in ['FRANCE', 'INTERNATIONAL']:
                zone_total = sum(len(articles) for articles in self.articles[zone].values())
                if zone_total > 0:
                    display_name = "FRANÇAIS" if zone == "FRANCE" else "ANGLAIS"
                    f.write(f"### {display_name} ({zone_total} articles)\n")
                    for category, articles in self.articles[zone].items():
                        if articles:
                            count = len(articles)
                            f.write(f"- **{category}**: {count} articles\n")
                    total_global += zone_total
                    f.write("\n")
            
            f.write(f"**Total global**: {total_global} articles\n\n")
            f.write("---\n\n")
            
            # Articles par zone et catégorie
            for zone in ['FRANCE', 'INTERNATIONAL']:
                zone_total = sum(len(articles) for articles in self.articles[zone].values())
                if zone_total > 0:
                    flag = "🇫🇷" if zone == "FRANCE" else "🌍"
                    display_name = "FRANÇAIS" if zone == "FRANCE" else "ANGLAIS"
                    f.write(f"# {flag} {display_name}\n\n")
                    
                    for category, articles in self.articles[zone].items():
                        if articles:
                            f.write(f"## {category}\n\n")
                            
                            for i, article in enumerate(articles, 1):
                                title = article['title']
                                link = article['link']
                                source = article['source']
                                
                                # Format plus propre avec numérotation
                                f.write(f"{i}. **[{title}]({link})**\n")
                                f.write(f"   - Source: *{source}*\n")
                                
                                if article['description']:
                                    # Nettoie davantage la description
                                    clean_desc = article['description'][:150].strip()
                                    if clean_desc:
                                        f.write(f"   - Description: {clean_desc}...\n")
                                
                                f.write("\n")
            
            # Footer
            f.write(f"\n*Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')} par Cyber Watch v3.0*\n")
        
        return filename

    def run(self):
        """Exécute la veille complète"""
        self.print_banner()
        
        print("🚀 Démarrage de la recherche...")
        print(f"⏰ Période: dernières 24h (depuis {self.time_limit.strftime('%d/%m/%Y %H:%M')})")
        print()
        
        # Collecte des données
        self.fetch_rss_feeds()
        
        self.fetch_cve_data()
        self.scrape_cert_fr()
        
        # Nettoyage
        print("🧹 Suppression des doublons...")
        self.remove_duplicates()
        
        # Génération des sorties
        self.generate_terminal_output()
        
        print("\n💾 Génération du fichier markdown...")
        markdown_file = self.generate_markdown_file()
        
        print(f"✅ Fichier généré: {markdown_file}")
        print(f"📍 Chemin complet: {os.path.abspath(markdown_file)}")
        
        print("\n🎉 Veille terminée avec succès!")

if __name__ == "__main__":
    try:
        cyber_watch = CyberWatchV3()
        cyber_watch.run()
    except KeyboardInterrupt:
        print("\n\n❌ Arrêt demandé par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n💥 Erreur fatale: {str(e)}")
        sys.exit(1)