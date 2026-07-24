# GovPay Common Auth 1.0.1

Prima release della libreria di autenticazione/autorizzazione condivisa di GovPay, sulla linea Spring Boot 4.x / Spring Framework 7.x. È una libreria Spring Boot **auto-configurata**: una volta aggiunta al classpath registra una **filter chain di sicurezza unica** che supporta tutti i metodi di autenticazione di GovPay, lasciando al consumer solo l'implementazione di una SPI minimale per risolvere il principal sul proprio data layer e l'abilitazione dei metodi via property.

## Funzionalita'

### Metodi di autenticazione

Ogni metodo è disabilitato di default e si attiva con `govpay.auth.<metodo>.enabled=true`. I metodi attivi convivono nella stessa chain: la libreria rileva automaticamente quale applicare in base alla request.

- **`BASIC`** — Basic Auth (username/password) verificata localmente
- **`LDAP`** — Basic Auth verificata su server LDAP esterno
- **`FORM`** — Login JSON `POST /auth/login` + sessione + CSRF cookie
- **`SSL`** — mTLS, certificato client X.509 nativo
- **`SSL_HEADER`** — Certificato client inoltrato via header da reverse proxy
- **`HEADER`** — Principal in header HTTP (pre-auth da proxy)
- **`API_KEY`** — Coppia id/key in header
- **`SPID`** — Principal SPID in header (IdP/shibboleth upstream)
- **`SESSION`** — Principal da attributo di `HttpSession`
- **`OAUTH2`** — Bearer token JWT (resource server)
- **`PUBLIC`** — Path in permitAll (anonymous)

### SPI per il consumer

- **`GovpayPrincipalLoader`** (obbligatoria) — unico punto di contatto col data layer: risolve il principal in un `AuthenticatedSubject` (password hash, abilitazione, ruoli)
- **`JsonLoginResponseWriter`** — personalizza il body della risposta di `POST /auth/login`
- **`AuthEventListener`** — riceve `onLoginSuccess` / `onLoginFailed` / `onLogout` per audit
- **`AuthenticationDetailsContributor`** — popola `Authentication.getDetails()` con attributi custom

### Caratteristiche

- **Chain unica con auto-detect** del metodo dalla request (precedenza first-wins per i pre-auth, BasicAuth valutato eagerly)
- **`application/problem+json` (RFC 9457)** ovunque: 401/403, sessione scaduta/invalida e CSRF failure
- **CSRF a cookie** (`XSRF-TOKEN`) per la FORM, allineato al pattern SPA Angular
- **Password encoder** SHA-512 Unix crypt (`$6$`) con fallback opzionale MD5 (`$1$`)
- **Rate limiter** sul login (tentativi per IP nella finestra configurabile)
- **Endpoint** `POST /auth/login`, `POST /auth/logout`, `POST /auth/oauth2/logout` (path configurabili)
- Tutto configurabile via property `govpay.auth.*` e sovrascrivibile dal consumer

## Stack tecnologico

- Java 21
- Spring Boot 4.1.0
- Spring Framework 7.0.8
- Spring Security 7.1.0 (core, LDAP, OAuth2 Resource Server)
- Jackson 3.1.4 (groupId `tools.jackson`)
- Parent POM `org.gov4j.govpay:govpay-bom:2.0.3`
- `jakarta.servlet-api` in scope `provided` (la porta il consumer)
- OWASP Dependency-Check 12.2.2, JaCoCo 0.8.14

## Pipeline CI/CD

- Build, test e code coverage (JaCoCo)
- Analisi qualita' codice su SonarCloud
- Verifica vulnerabilita' dipendenze: OWASP Dependency-Check (NVD + OSS Index) e OSV Scanner (SARIF)
- Analisi compatibilita' licenze
- Generazione **SBOM CycloneDX** (json + xml) tramite `cyclonedx-maven-plugin`
- Gating obbligatorio `build + osv-scan + sbom` prima di ogni step di deploy o release
- Cache OWASP Dependency-Check versionata sulla `owasp.plugin.version` (bump del plugin → cache invalidata) e refresh notturno del DB NVD via workflow schedulato
- Pubblicazione SNAPSHOT su Maven Central su push in `main`
- Release automatica su tag con JAR firmato e archivio `release-reports-{tag}.zip` contenente report OWASP, JaCoCo, OSV, SBOM e licenze

## Artefatto Maven

```xml
<dependency>
    <groupId>org.gov4j.govpay</groupId>
    <artifactId>govpay-common-auth</artifactId>
    <version>1.0.1</version>
</dependency>
```

## Licenza

GNU GPL v3 — Copyright (c) 2014-2026 Link.it srl
