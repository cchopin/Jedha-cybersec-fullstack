# ============================================
# SCRIPT 01 : Installation IIS + Portail Web
# ============================================
# Ce script :
# 1. Installe le role IIS (Web Server) sur SRV1
# 2. Deploie un site web statique marketing StellarTech
# 3. Configure le site dans IIS
#
# Prerequis : Executer sur SRV1 (deja joint au domaine stellar.local)
# ============================================

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Installation IIS + Portail Web Interne"
Write-Host "==========================================" -ForegroundColor Cyan

# ============================================
# PARTIE 1 : Installation du role IIS
# ============================================
Write-Host "`n[1/4] Installation du role Web Server (IIS)..." -ForegroundColor Yellow

Install-WindowsFeature -Name Web-Server -IncludeManagementTools -IncludeAllSubFeature

Write-Host "  IIS installe avec succes" -ForegroundColor Green

# ============================================
# PARTIE 2 : Creer le site web statique
# ============================================
Write-Host "`n[2/4] Creation du portail web StellarTech..." -ForegroundColor Yellow

$wwwroot = "C:\inetpub\wwwroot"

# Sauvegarder la page par defaut IIS
if (Test-Path "$wwwroot\iisstart.htm") {
    Rename-Item "$wwwroot\iisstart.htm" "$wwwroot\iisstart.htm.bak" -Force -ErrorAction SilentlyContinue
}

# Creer le fichier CSS
$css = @"
/* StellarTech Intranet - Stylesheet */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: #0a0e27;
    color: #e0e0e0;
    line-height: 1.6;
}

/* Header */
.header {
    background: linear-gradient(135deg, #1a1f4e 0%, #0d1137 100%);
    border-bottom: 2px solid #4a90d9;
    padding: 20px 0;
    position: sticky;
    top: 0;
    z-index: 100;
}

.header-content {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.logo {
    display: flex;
    align-items: center;
    gap: 15px;
}

.logo-icon {
    font-size: 2.5em;
}

.logo h1 {
    font-size: 1.8em;
    color: #4a90d9;
    font-weight: 700;
}

.logo span {
    font-size: 0.9em;
    color: #8899aa;
    display: block;
}

nav ul {
    list-style: none;
    display: flex;
    gap: 30px;
}

nav a {
    color: #b0c4de;
    text-decoration: none;
    font-weight: 500;
    transition: color 0.3s;
}

nav a:hover {
    color: #4a90d9;
}

/* Hero Section */
.hero {
    background: linear-gradient(135deg, #0d1137 0%, #1a237e 50%, #0d1137 100%);
    padding: 80px 20px;
    text-align: center;
}

.hero h2 {
    font-size: 2.5em;
    color: #ffffff;
    margin-bottom: 15px;
}

.hero p {
    font-size: 1.2em;
    color: #8899aa;
    max-width: 600px;
    margin: 0 auto 30px;
}

.hero-badge {
    display: inline-block;
    background: rgba(74, 144, 217, 0.2);
    border: 1px solid #4a90d9;
    padding: 8px 20px;
    border-radius: 20px;
    color: #4a90d9;
    font-size: 0.9em;
}

/* Cards Section */
.section {
    max-width: 1200px;
    margin: 0 auto;
    padding: 60px 20px;
}

.section-title {
    text-align: center;
    font-size: 2em;
    color: #4a90d9;
    margin-bottom: 40px;
}

.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 25px;
}

.card {
    background: linear-gradient(145deg, #111640 0%, #0d1137 100%);
    border: 1px solid #1e2a5a;
    border-radius: 12px;
    padding: 30px;
    transition: transform 0.3s, border-color 0.3s;
}

.card:hover {
    transform: translateY(-5px);
    border-color: #4a90d9;
}

.card-icon {
    font-size: 2.5em;
    margin-bottom: 15px;
}

.card h3 {
    color: #ffffff;
    font-size: 1.3em;
    margin-bottom: 10px;
}

.card p {
    color: #8899aa;
    font-size: 0.95em;
}

/* News Section */
.news {
    background: #0d1137;
    padding: 60px 20px;
}

.news-list {
    max-width: 800px;
    margin: 0 auto;
}

.news-item {
    background: rgba(26, 31, 78, 0.5);
    border-left: 3px solid #4a90d9;
    padding: 20px 25px;
    margin-bottom: 15px;
    border-radius: 0 8px 8px 0;
}

.news-item h4 {
    color: #ffffff;
    margin-bottom: 5px;
}

.news-item .date {
    color: #4a90d9;
    font-size: 0.85em;
    margin-bottom: 8px;
}

.news-item p {
    color: #8899aa;
}

/* Resources Section */
.resources {
    max-width: 1200px;
    margin: 0 auto;
    padding: 60px 20px;
}

.resource-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
}

.resource-link {
    display: flex;
    align-items: center;
    gap: 15px;
    background: #111640;
    border: 1px solid #1e2a5a;
    border-radius: 8px;
    padding: 20px;
    text-decoration: none;
    color: #e0e0e0;
    transition: border-color 0.3s;
}

.resource-link:hover {
    border-color: #4a90d9;
}

.resource-link .icon {
    font-size: 1.8em;
}

/* Footer */
.footer {
    background: #080b1f;
    border-top: 1px solid #1e2a5a;
    padding: 30px 20px;
    text-align: center;
    color: #556677;
    font-size: 0.9em;
}
"@

$css | Out-File -FilePath "$wwwroot\style.css" -Encoding UTF8

Write-Host "  Fichier CSS cree" -ForegroundColor Green

# ============================================
# PARTIE 3 : Creer la page HTML
# ============================================
Write-Host "`n[3/4] Creation de la page HTML du portail..." -ForegroundColor Yellow

$html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StellarTech - Portail Interne</title>
    <link rel="stylesheet" href="style.css">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>&#11088;</text></svg>">
</head>
<body>
    <!-- Header -->
    <header class="header">
        <div class="header-content">
            <div class="logo">
                <span class="logo-icon">&#11088;</span>
                <div>
                    <h1>StellarTech</h1>
                    <span>Portail Interne</span>
                </div>
            </div>
            <nav>
                <ul>
                    <li><a href="#accueil">Accueil</a></li>
                    <li><a href="#services">Services</a></li>
                    <li><a href="#actualites">Actualites</a></li>
                    <li><a href="#ressources">Ressources</a></li>
                </ul>
            </nav>
        </div>
    </header>

    <!-- Hero -->
    <section class="hero" id="accueil">
        <h2>Bienvenue sur l'Intranet StellarTech</h2>
        <p>L'espace centralise pour les ressources, guidelines et annonces de l'entreprise.</p>
        <span class="hero-badge">&#128274; Acces reserve aux employes connectes via VPN</span>
    </section>

    <!-- Services -->
    <section class="section" id="services">
        <h2 class="section-title">Nos Services Internes</h2>
        <div class="cards">
            <div class="card">
                <div class="card-icon">&#127912;</div>
                <h3>Brand Guidelines</h3>
                <p>Les chartes graphiques, logos, palettes de couleurs et templates officiels StellarTech sont disponibles ici.</p>
            </div>
            <div class="card">
                <div class="card-icon">&#128196;</div>
                <h3>Documentation</h3>
                <p>Guides techniques, procedures internes et documentation de nos projets en cours.</p>
            </div>
            <div class="card">
                <div class="card-icon">&#128101;</div>
                <h3>Ressources RH</h3>
                <p>Formulaires, politiques RH, informations sur les avantages et le programme de formation.</p>
            </div>
            <div class="card">
                <div class="card-icon">&#128187;</div>
                <h3>Support IT</h3>
                <p>Soumission de tickets, FAQ et guides de depannage courants.</p>
            </div>
            <div class="card">
                <div class="card-icon">&#128200;</div>
                <h3>Rapports</h3>
                <p>Tableaux de bord, KPIs et rapports mensuels de performance par departement.</p>
            </div>
            <div class="card">
                <div class="card-icon">&#128640;</div>
                <h3>Projets</h3>
                <p>Suivi des projets en cours, jalons et calendrier des releases a venir.</p>
            </div>
        </div>
    </section>

    <!-- Actualites -->
    <section class="news" id="actualites">
        <h2 class="section-title">Dernieres Actualites</h2>
        <div class="news-list">
            <div class="news-item">
                <div class="date">4 Mars 2026</div>
                <h4>Lancement du Portail Interne</h4>
                <p>Le nouveau portail interne StellarTech est desormais accessible via VPN. Tous les employes peuvent y acceder a http://internal.stellar.local</p>
            </div>
            <div class="news-item">
                <div class="date">1 Mars 2026</div>
                <h4>Mise a jour de la charte graphique</h4>
                <p>La nouvelle identite visuelle StellarTech est disponible. Les nouveaux assets sont a telecharger dans la section Brand Guidelines.</p>
            </div>
            <div class="news-item">
                <div class="date">25 Fevrier 2026</div>
                <h4>Formation Cybersecurite obligatoire</h4>
                <p>Tous les employes doivent completer la formation cybersecurite avant le 15 mars. Inscription via le portail RH.</p>
            </div>
            <div class="news-item">
                <div class="date">20 Fevrier 2026</div>
                <h4>Nouveau programme de parrainage</h4>
                <p>StellarTech lance son programme de cooptation. Recommander un talent pour recevoir une prime. Details aupres des RH.</p>
            </div>
        </div>
    </section>

    <!-- Ressources -->
    <section class="resources" id="ressources">
        <h2 class="section-title">Acces Rapide</h2>
        <div class="resource-grid">
            <a href="#" class="resource-link">
                <span class="icon">&#128193;</span>
                <div>
                    <strong>Partages Engineering</strong>
                    <br><small>\\SRV1\share_engineering</small>
                </div>
            </a>
            <a href="#" class="resource-link">
                <span class="icon">&#128193;</span>
                <div>
                    <strong>Partages Marketing</strong>
                    <br><small>\\SRV1\share_marketing</small>
                </div>
            </a>
            <a href="#" class="resource-link">
                <span class="icon">&#128193;</span>
                <div>
                    <strong>Partages RH</strong>
                    <br><small>\\SRV1\share_hr</small>
                </div>
            </a>
            <a href="#" class="resource-link">
                <span class="icon">&#128231;</span>
                <div>
                    <strong>Contact IT</strong>
                    <br><small>support@stellar.local</small>
                </div>
            </a>
        </div>
    </section>

    <!-- Footer -->
    <footer class="footer">
        <p>&copy; 2026 StellarTech Inc. - Portail Interne | Acces reserve via VPN</p>
        <p>Infrastructure : DC1 (10.0.0.10) | DC2 (10.0.0.11) | SRV1 (10.0.0.20)</p>
    </footer>
</body>
</html>
"@

$html | Out-File -FilePath "$wwwroot\index.html" -Encoding UTF8

Write-Host "  Page HTML creee : $wwwroot\index.html" -ForegroundColor Green

# ============================================
# PARTIE 4 : Configurer IIS
# ============================================
Write-Host "`n[4/4] Configuration du site IIS..." -ForegroundColor Yellow

Import-Module WebAdministration

# Configurer le document par defaut
Set-WebConfigurationProperty -Filter "/system.webServer/defaultDocument/files" `
    -PSPath "IIS:\Sites\Default Web Site" `
    -Name "." `
    -Value @{value="index.html"} -ErrorAction SilentlyContinue

# Verification que le site ecoute sur le port 80
Write-Host "  Site IIS configure sur le port 80" -ForegroundColor Green

# Verifier que le site est demarre
Start-Website -Name "Default Web Site" -ErrorAction SilentlyContinue

# ============================================
# VERIFICATION
# ============================================
Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host " Verification" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Tester l'acces local
try {
    $response = Invoke-WebRequest -Uri "http://localhost" -UseBasicParsing -ErrorAction Stop
    Write-Host "  Site accessible localement : HTTP $($response.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "  ERREUR : Le site n'est pas accessible" -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
}

# Lister les fichiers du site
Write-Host "`n  Fichiers deployes :" -ForegroundColor Cyan
Get-ChildItem $wwwroot -File | ForEach-Object {
    Write-Host "    - $($_.Name) ($([math]::Round($_.Length/1KB, 1)) KB)" -ForegroundColor White
}

Write-Host "`n  Prochaine etape : Executer 02_create_vpn_group.ps1 sur DC1" -ForegroundColor Yellow
