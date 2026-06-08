# Pipeline di Validazione CI/CD

Questo progetto utilizza GitHub Actions per la validazione automatica del codice e la creazione di release.

## Workflow Maven

Il workflow principale (`.github/workflows/maven.yml`) esegue i seguenti passaggi:

### Job: Build

1. **Setup Ambiente**
   - Checkout del codice
   - Configurazione timezone Europe/Rome
   - Setup JDK 21 (Temurin distribution)
   - Cache delle dipendenze Maven

2. **Security Scanning**
   - Cache del database OWASP Dependency-Check
   - Verifica delle vulnerabilità note (NVD)
   - Generazione report di sicurezza (HTML e XML)

3. **Build e Test**
   - Compilazione del progetto: `mvn clean install`
   - Esecuzione dei test unitari
   - Generazione report di code coverage con JaCoCo

4. **Code Quality Analysis**
   - Scansione SonarCloud per analisi statica del codice
   - Verifica qualità, bugs, vulnerabilità, code smells
   - Report di copertura del codice

5. **License Analysis**
   - Download delle informazioni sulle licenze delle dipendenze
   - Analisi automatica della compatibilità delle licenze
   - Validazione contro le licenze approvate
   - Generazione report dettagliato in formato CSV e JSON
   - Gestione eccezioni tramite file di configurazione

6. **Artifact Upload**
   - JAR della libreria
   - Report JaCoCo (XML e ZIP HTML)
   - Report OWASP Dependency-Check (HTML e XML)
   - Report License Analysis (third-party-licenses/)

### Job: Release

Eseguito solo quando viene creato un tag Git:

1. **Preparazione Artifact**
   - Download degli artifact dal job build
   - Rinomina del JAR con il numero di versione (tag)

2. **GitHub Release**
   - Creazione automatica della release su GitHub
   - Upload dei seguenti file:
     - `govpay-common-auth-{version}.jar`
     - `jacoco.xml` (report coverage)
     - `jacoco-html-report.zip` (report coverage HTML)
     - `dependency-check-report.html` (report sicurezza)
     - `dependency-check-report.xml` (report sicurezza XML)
     - `third-party-licenses.zip` (report licenze dipendenze)

## Secrets Richiesti

Configura i seguenti secrets nel repository GitHub (Settings -> Secrets and variables -> Actions):

| Secret | Descrizione | Obbligatorio |
|--------|-------------|--------------|
| `NVD_API_KEY` | API Key per il National Vulnerability Database | Consigliato |
| `SONAR_TOKEN` | Token di autenticazione SonarCloud | Si |
| `GH_TOKEN` | GitHub Personal Access Token per release e dependency graph | Si |
| `CENTRAL_USERNAME` | Username Maven Central (variabile, non secret) | Si (per deploy) |
| `CENTRAL_TOKEN` | Token Maven Central | Si (per deploy) |
| `GPG_PRIVATE_KEY` | Chiave privata GPG per firmare gli artifact | Si (per release) |
| `GPG_PASSPHRASE` | Passphrase della chiave GPG | Si (per release) |

### Come ottenere i secrets:

**NVD_API_KEY:**
1. Registrati su https://nvd.nist.gov/developers/request-an-api-key
2. Riceverai la chiave via email
3. Aggiungi come secret nel repository GitHub

**SONAR_TOKEN:**
1. Accedi a SonarCloud (https://sonarcloud.io)
2. Vai su Account -> Security
3. Genera un nuovo token
4. Aggiungi come secret nel repository GitHub

**GH_TOKEN:**
1. Vai su GitHub Settings -> Developer settings -> Personal access tokens -> Tokens (classic)
2. Genera un nuovo token con i permessi:
   - `repo` (full control)
   - `write:packages`
3. Aggiungi come secret nel repository GitHub

## SonarCloud Setup

1. Importa il progetto su SonarCloud
2. Configura l'organizzazione: `link-it`
3. Verifica che il projectKey sia: `link-it_govpay-common-auth`
4. Il file `sonar-project.properties` contiene la configurazione

## Trigger della Pipeline

### Push su main
```bash
git push origin main
```
Esegue: Build, test, security scan, code quality analysis

### Pull Request su main
```bash
# Quando crei una PR verso main
```
Esegue: Build, test, security scan, code quality analysis

### Creazione Tag (Release)
```bash
# Crea un tag per la versione
git tag 1.0.0
git push origin 1.0.0
```
Esegue: Build completo + creazione release GitHub con tutti gli artifact

## Plugin Maven Configurati

### JaCoCo (Code Coverage)
- **Versione:** da BOM (`jacoco.version`)
- **Report:** `target/site/jacoco/`
- **Esclusi:** Test classes e package di test
- **Comando locale:** `mvn verify` (genera il report)

### OWASP Dependency-Check
- **Versione:** da BOM (`owasp.plugin.version`)
- **Report:** `target/dependency-check-report.html`
- **Fase:** verify
- **Soglia CVSS:** 11 (non blocca la build per vulnerabilita)
- **Comando locale:** `mvn verify` (esegue il check)
- **Cache:** `.dependency-check/data` (esclusa da Git)

## Esecuzione Locale

### Build completo con tutti i check
```bash
mvn clean install
```

### Solo build e test (senza security check)
```bash
mvn clean install -Dowasp.phase=none
```

### Solo security check
```bash
mvn dependency-check:aggregate
```

### Solo code coverage
```bash
mvn clean test jacoco:report
```

### Visualizzare il report JaCoCo
```bash
open target/site/jacoco/index.html
```

### Visualizzare il report OWASP
```bash
open target/dependency-check-report.html
```

## Configurazione Avanzata

### Disabilitare OWASP Dependency-Check
Nel `pom.xml`, modifica:
```xml
<owasp.phase>none</owasp.phase>
```

### Modificare la soglia CVSS
Nel `pom.xml`, modifica:
```xml
<owasp.failBuildOnCVSS>7</owasp.failBuildOnCVSS>
```
Valori:
- `11`: Non blocca mai (default)
- `7`: Blocca per vulnerabilita HIGH
- `4`: Blocca per vulnerabilita MEDIUM

### Disabilitare auto-update OWASP DB
Utile quando il repository NIST ha problemi:
```xml
<owasp.autoUpdate>false</owasp.autoUpdate>
```

## License Analysis

L'analisi delle licenze verifica automaticamente la compatibilita delle dipendenze con i requisiti di licenza del progetto.

### Funzionalita

Lo script Python (`analyze_licenses.py`) analizza:
- **Compatibilita GPLv3**: Verifica che tutte le licenze siano compatibili con GPLv3
- **Enterprise Safety**: Identifica licenze problematiche per uso enterprise
- **Licenze Sconosciute**: Segnala dipendenze senza licenza o con licenze non riconosciute
- **Report Dettagliati**: Genera CSV e JSON con dettagli completi

### Licenze Supportate

Il tool riconosce e valida:
- Apache 2.0 (tutte le varianti)
- MIT, BSD-2-Clause, BSD-3-Clause
- Eclipse (EPL-1.0, EPL-2.0, EDL-1.0)
- LGPL (2.1, 3.0)
- MPL-2.0
- GPL con eccezioni (Classpath Exception, FOSS Exception)

### File di Eccezioni

Le eccezioni sono configurate in `.github/workflows/scripts/license-exceptions.json`:

```json
{
  "exceptions": [
    {
      "groupId": "org.example",
      "artifactId": "some-artifact",
      "reason": "Spiegazione del motivo dell'eccezione",
      "exclude_from_reports": true
    }
  ]
}
```

Campi disponibili:
- `groupId`: Maven groupId (supporta wildcard `*`)
- `artifactId`: Maven artifactId (supporta wildcard `*`)
- `reason`: Motivazione dell'eccezione (obbligatorio)
- `exclude_from_reports`: Se `true`, escluso completamente dai report

### Report Generati

La directory `third-party-licenses/` contiene:
- `license-summary.json`: Report in formato JSON
- `license-artifacts-mapping.csv`: Report in formato CSV
- `license-compatibility-report.html`: Report HTML interattivo
- `license-compatibility-report.md`: Report in formato Markdown

### Esecuzione Locale

```bash
# Download informazioni licenze
mvn org.codehaus.mojo:license-maven-plugin:2.4.0:aggregate-download-licenses \
  -DexcludeScopes=test,provided,system \
  -DincludeTransitiveDependencies=true

# Analisi licenze
python3 .github/workflows/scripts/analyze_licenses.py \
  --exceptions .github/workflows/scripts/license-exceptions.json
```

### Gestione Licenze Problematiche

Se l'analisi identifica problemi:

1. **Licenza sconosciuta**: Aggiorna il database licenze in `analyze_licenses.py`
2. **Licenza incompatibile**:
   - Trova un'alternativa alla dipendenza
   - O aggiungi un'eccezione giustificata
3. **Dipendenza senza licenza**: Contatta il maintainer o evita la dipendenza

## Troubleshooting

### Build fallisce per timeout OWASP
- Aumentare `nvdApiDelay` nel pom.xml
- Verificare la connessione internet
- Usare `NVD_API_KEY` per aumentare il rate limit

### SonarCloud non riceve i dati
- Verificare che `SONAR_TOKEN` sia configurato correttamente
- Controllare che l'organizzazione e projectKey siano corretti
- Verificare che il report JaCoCo sia generato: `target/site/jacoco/jacoco.xml`

### Release non viene creata
- Verificare che `GH_TOKEN` abbia i permessi corretti
- Il workflow release si attiva solo con i tag: `git push origin <tag>`
- Verificare i log del job release in GitHub Actions

## Badge per README

Aggiungi questi badge al tuo README.md:

```markdown
[![Java CI with Maven](https://github.com/link-it/govpay-common-auth/actions/workflows/maven.yml/badge.svg)](https://github.com/link-it/govpay-common-auth/actions/workflows/maven.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=link-it_govpay-common-auth&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=link-it_govpay-common-auth)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=link-it_govpay-common-auth&metric=coverage)](https://sonarcloud.io/summary/new_code?id=link-it_govpay-common-auth)
```
