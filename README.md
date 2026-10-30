<p align="center">
<img src="https://www.link.it/wp-content/uploads/2025/01/logo-govpay.svg" alt="GovPay Logo" width="200"/>
</p>

# GovPay - Porta di accesso al sistema pagoPA - Common Auth

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=link-it_govpay-common-auth&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=link-it_govpay-common-auth)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://raw.githubusercontent.com/link-it/govpay-common-auth/main/LICENSE)
[![Spring Boot](https://img.shields.io/badge/dynamic/xml?url=https%3A%2F%2Fraw.githubusercontent.com%2Flink-it%2Fgovpay-bom%2Fmain%2Fpom.xml&query=%2F%2F*%5Blocal-name()%3D'spring-boot.version'%5D&label=Spring%20Boot&color=brightgreen)](https://spring.io/projects/spring-boot)
[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/projects/jdk/21/)

Libreria Spring Boot di autenticazione per le API GovPay: registra una catena Spring Security unica che supporta tutti i metodi di autenticazione di GovPay (Basic, LDAP, login JSON con sessione, certificato client, certificato da header, header, API key, SPID, sessione, OAuth2) e lascia al progetto che la usa solo il caricamento delle utenze.

## Sommario

La libreria non è un'applicazione: è un jar auto-configurato che le API GovPay includono come dipendenza Maven. Una volta nel classpath, e in presenza di un bean `GovpayPrincipalLoader` fornito dal progetto, registra:

- una `SecurityFilterChain` unica (`securityMatcher("/**")`) che riconosce dalla richiesta il metodo di autenticazione da applicare;
- i filtri dei metodi abilitati con `govpay.auth.<metodo>.enabled=true` (tutti disabilitati di default);
- le risposte di errore in `application/problem+json` (RFC 9457) per 401, 403, sessione scaduta o non valida e token CSRF errato;
- il `PasswordEncoder` compatibile con le password di GovPay (SHA-512 Unix crypt `$6$`, con lettura opzionale delle MD5 `$1$`);
- header di sicurezza, `HttpFirewall`, CORS e path pubblici configurabili.

La libreria autentica: verifica le credenziali e costruisce l'utenza con i ruoli restituiti dal progetto. Le autorizzazioni applicative (ACL, domini, tipi pendenza) restano al progetto, che può usare `AutorizzazioneDominio` per la regola comune "tutti i domini oppure il dominio specifico".

| Package | Contenuto |
|---------|-----------|
| `it.govpay.common.auth` | Auto-configurazioni, proprietà `govpay.auth.*`, filtri dei metodi, entry point e handler `problem+json`, `GovpayPasswordEncoder`, validatori JWT, `AuthTypeAccessor`, `AutorizzazioneDominio` |
| `it.govpay.common.auth.spi` | Interfacce che il progetto implementa (`GovpayPrincipalLoader`, `JsonLoginResponseWriter`, `AuthEventListener`, `AuthenticationDetailsContributor`) e tipi scambiati (`AuthenticatedSubject`, `AuthType`, `FailureReason`) |

Le auto-configurazioni sono registrate in [src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports](src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports): `GovpayAuthAutoConfiguration` (password encoder, entry point, firewall, adattatori delle utenze) e `GovpaySecurityFilterChainAutoConfiguration` (filtri e catena). Ogni bean è condizionato ai flag `govpay.auth.*` e quasi tutti sono `@ConditionalOnMissingBean`, quindi sostituibili dal progetto.

## Integrazione con GovPay

| Componente | Quando serve | Obbligatorio | Ruolo |
|------------|--------------|--------------|-------|
| [govpay-bom](https://github.com/link-it/govpay-bom) | build | sì | Parent Maven: versioni di Spring Boot, Spring Security, Jackson e dei plugin (compresa l'analisi OWASP) |
| `GovpayPrincipalLoader` del progetto | runtime | sì | Bean che carica le utenze. Senza di esso la catena della libreria non viene registrata e resta la sicurezza di default di Spring Boot: ogni richiesta risponde 401 (vedi [Utilizzo](#utilizzo)) |
| Database di GovPay | runtime | - | La libreria non accede al database. Sono i `GovpayPrincipalLoader` dei progetti a leggere le utenze (operatori e applicazioni) dalle tabelle del core |
| Server LDAP | runtime | no | Verifica delle credenziali Basic con il metodo `LDAP` (`govpay.auth.ldap.*`) |
| Identity Provider OAuth2/OIDC | runtime | no | Chiavi pubbliche (JWK Set) per i token Bearer del metodo `OAUTH2` ed eventuale logout OIDC (`govpay.auth.oauth2.*`) |
| Reverse proxy, API gateway o proxy SPID | runtime | no | Inoltrano il certificato client (`SSL_HEADER`), il principal già autenticato (`HEADER`) o il codice fiscale SPID (`SPID`) negli header della richiesta |
| Progetti che usano la libreria | build | - | Dipendenza diretta nel `pom.xml`: [govpay-console-api](https://github.com/link-it/govpay-console-api), [govpay-pafornode-api](https://github.com/link-it/govpay-pafornode-api), [govpay-pendenze-api](https://github.com/link-it/govpay-pendenze-api), [govpay-riconciliazioni-api](https://github.com/link-it/govpay-riconciliazioni-api) |

## Compilazione

Requisiti: JDK 21 e Maven 3.8.1 o successivo.

```bash
mvn clean install
```

Il risultato è `target/govpay-common-auth-<versione>.jar` (più i jar dei sorgenti e della Javadoc), installato nel repository Maven locale. La build esegue i test con il report di copertura JaCoCo (`target/site/jacoco/`) e, nella fase `verify`, l'analisi OWASP Dependency-Check delle dipendenze (esecuzione `check-owasp` ereditata da govpay-bom). Per escludere l'analisi OWASP, per esempio in sviluppo:

```bash
mvn clean install -Dowasp.phase=none
```

Altri comandi utili:

```bash
# Solo i test
mvn clean test

# Test singolo
mvn test -Dtest=GovpaySecurityFilterChainAutoConfigurationTest
mvn test -Dtest=GovpayPasswordEncoderTest#matchesPreEncodedSha512
```

### SBOM (CycloneDX)

La pipeline CI/CD genera un SBOM in formato CycloneDX (JSON + XML) con `cyclonedx-maven-plugin` su push di `main` e sui tag, lo pubblica come artefatto `sbom-report` e lo carica su Dependency-Track. Dettagli della pipeline in [.github/PIPELINE.md](.github/PIPELINE.md).

## Utilizzo

Coordinate Maven:

```xml
<dependency>
    <groupId>org.gov4j.govpay</groupId>
    <artifactId>govpay-common-auth</artifactId>
    <version>${govpay-common-auth.version}</version>
</dependency>
```

L'ultima versione rilasciata su Maven Central è `1.0.1`; quella di sviluppo è `1.0.2-SNAPSHOT` (pom su `main`), pubblicata su `https://central.sonatype.com/repository/maven-snapshots`. I progetti GovPay la impostano con la proprietà `govpay-common-auth.version`.

### Cosa deve fornire il progetto

1. **Un'applicazione web servlet** con Spring Boot 4 (versione del parent govpay-bom): la dipendenza `jakarta.servlet-api` della libreria è `provided`, il container lo porta il progetto (es. `spring-boot-starter-web`).
2. **Un `ObjectMapper` Jackson 3** (`tools.jackson.databind.ObjectMapper`) nel contesto, usato per scrivere le risposte `problem+json`: Spring Boot lo registra in ogni applicazione web.
3. **Un bean `GovpayPrincipalLoader`** (obbligatorio). Tutta `GovpaySecurityFilterChainAutoConfiguration` è condizionata a `@ConditionalOnBean(GovpayPrincipalLoader.class)`: se il bean manca non vengono registrati né la catena né i filtri, nessun metodo `govpay.auth.*` ha effetto e resta la configurazione di default di Spring Boot, che richiede l'autenticazione su ogni path con un utente generato all'avvio. Il sintomo è un 401 su tutte le richieste, path pubblici compresi.
4. **Le proprietà `govpay.auth.<metodo>.enabled=true`** dei metodi da attivare e, se servono, i path pubblici (`govpay.auth.public-chain.*`).

Non serve una `@Configuration` di sicurezza nel progetto. Una `SecurityFilterChain` aggiuntiva del progetto si affianca a quella della libreria (ordine `50`, matcher `/**`): per i path che deve gestire va registrata con un ordine più basso e un `securityMatcher` specifico.

### `GovpayPrincipalLoader`

Dato il principal estratto dalla richiesta e l'`AuthType` del metodo applicato, restituisce un `AuthenticatedSubject` con hash della password, flag di abilitazione e ruoli, oppure `null` se l'utenza non esiste (la libreria risponde 401).

```java
@Component
public class ConsoleGovpayPrincipalLoader implements GovpayPrincipalLoader {

    private final UtenzaRepository utenzaRepository;

    public ConsoleGovpayPrincipalLoader(UtenzaRepository utenzaRepository) {
        this.utenzaRepository = utenzaRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public AuthenticatedSubject load(String principal, AuthType authType) {
        Utenza utenza = utenzaRepository.findByPrincipal(principal).orElse(null);
        if (utenza == null) {
            return null;
        }
        boolean enabled = Boolean.TRUE.equals(utenza.getAbilitato());
        List<String> roles = parseRoles(utenza.getRuoli());
        return new AuthenticatedSubject(utenza.getPrincipal(), utenza.getPassword(), enabled, roles);
    }
}
```

- `passwordHash` serve ai metodi con password (`BASIC`, `FORM`, `API_KEY`) e deve essere verificabile da `GovpayPasswordEncoder`: SHA-512 Unix crypt `$6$` oppure, se `govpay.auth.password.md5-fallback-enabled=true`, MD5 Unix crypt `$1$`. Per gli altri metodi può essere `null`.
- `enabled=false` fa fallire l'autenticazione (utenza disabilitata).
- Ai ruoli viene aggiunto il prefisso `ROLE_` se manca.
- L'`AuthType` permette di cercare l'utenza in modo diverso per metodo (es. per `SSL` e `SSL_HEADER` il principal è il subject DN del certificato, per `SPID` il codice fiscale).
- Il loader è invocato a ogni autenticazione (con i metodi senza sessione, a ogni richiesta) e deve essere thread-safe.

### Metodi di autenticazione

Ogni metodo è disabilitato di default e si attiva con `govpay.auth.<metodo>.enabled=true`. I codici `AuthType` sono stabili verso l'esterno: i progetti li espongono nei propri endpoint (es. `Profilo.autenticazione` e `GET /auth/methods` di govpay-console-api).

| `AuthType` | Prefisso delle proprietà | Credenziale |
|------------|--------------------------|-------------|
| `BASIC` | `govpay.auth.basic` | Basic Auth (username/password) verificata con il loader e `GovpayPasswordEncoder` |
| `LDAP` | `govpay.auth.ldap` | Basic Auth verificata con un bind su un server LDAP; l'utenza deve esistere anche nel loader |
| `FORM` | `govpay.auth.form` | Login JSON `POST /auth/login`, poi sessione (`JSESSIONID`) e token CSRF in cookie |
| `SSL` | `govpay.auth.ssl` | Certificato client X.509 della connessione TLS (mTLS terminata nel container) |
| `SSL_HEADER` | `govpay.auth.ssl-header` | Certificato client inoltrato in un header dal reverse proxy |
| `HEADER` | `govpay.auth.header` | Principal in un header HTTP, autenticato a monte dal proxy |
| `API_KEY` | `govpay.auth.api-key` | Coppia id/chiave in due header; la chiave è verificata come una password |
| `SPID` | `govpay.auth.spid` | Codice fiscale in un header impostato dal proxy SPID (Shibboleth o simili), con sessione |
| `SESSION` | `govpay.auth.session` | Principal letto da un attributo della `HttpSession`, impostato da un altro componente del progetto |
| `OAUTH2` | `govpay.auth.oauth2` | Token Bearer JWT (resource server) |
| `PUBLIC` | `govpay.auth.public-chain` | Path accessibili senza autenticazione |

I metodi attivi convivono nella stessa catena: ogni filtro si attiva solo se nella richiesta trova la propria credenziale (header, certificato, sessione, token). `AuthTypeAccessor.current(request)` restituisce al controller il metodo con cui la richiesta è stata autenticata (vedi [Funzionamento della catena](#funzionamento-della-catena)).

### SPI

| SPI | Obbligatoria | Default se assente |
|-----|:------------:|--------------------|
| `GovpayPrincipalLoader` | **sì** | nessuno: senza bean la catena non viene registrata |
| `JsonLoginResponseWriter` | no | `DefaultJsonLoginResponseWriter`, scrive `{"principal":"...","autenticazione":"FORM"}` |
| `AuthEventListener` | no | no-op |
| `AuthenticationDetailsContributor` | no | `DefaultAuthenticationDetailsContributor`, delega a `WebAuthenticationDetailsSource` di Spring |

- **`JsonLoginResponseWriter`**: scrive il corpo della risposta di `POST /auth/login` riuscito (tipicamente il profilo dell'utente con ACL e domini).
- **`AuthEventListener`**: riceve `onLoginSuccess`, `onLoginFailed` (con `FailureReason`: `BAD_CREDENTIALS`, `DISABLED`, `RATE_LIMITED`, `INTERNAL_ERROR`) e `onLogout` del login JSON e del logout di sessione, per l'audit del progetto.
- **`AuthenticationDetailsContributor`**: costruisce `Authentication.getDetails()` per i metodi `API_KEY`, `HEADER`, `SSL_HEADER`, `SPID`, `SESSION`, `LDAP` e `FORM` (header tracciati, IP, attributi SPID).

### Endpoint esposti dalla libreria

| Endpoint | Metodo | Attivo quando | Risposta |
|----------|--------|---------------|----------|
| `/auth/login` (`govpay.auth.form.login-path`) | POST | `form.enabled=true` | Corpo `{"username":"...","password":"..."}`. 200 con il corpo scritto da `JsonLoginResponseWriter`, cookie di sessione e cookie `XSRF-TOKEN`; 400 se il corpo non è valido, 401 se le credenziali sono errate o l'utenza è disabilitata, 429 oltre il limite di tentativi falliti |
| `/auth/logout` (`govpay.auth.form.logout-path`) | POST | `form.enabled=true` oppure `spid.enabled=true` | 204: invalida la sessione e cancella i cookie `JSESSIONID` e `XSRF-TOKEN` |
| `/auth/oauth2/logout` (`govpay.auth.oauth2.logout-path`) | POST | `oauth2.enabled=true` con `logout-uri` e `post-logout-redirect-uri` valorizzati | 200 con `{"logoutUrl":"..."}`, l'URL di logout dell'IdP con `post_logout_redirect_uri` e, se passato come parametro, `id_token_hint` |

`GET /auth/methods` non è fornito dalla libreria: è un endpoint dei progetti che espone al frontend i metodi attivi.

### Esempio di configurazione (govpay-console-api)

```properties
# Metodi attivi
govpay.auth.basic.enabled=true
govpay.auth.form.enabled=true

# Path pubblici (documentazione OpenAPI ed endpoint dei metodi)
govpay.auth.public-chain.enabled=true
govpay.auth.public-chain.permit-all-paths[0].path=/openapi/openapi.yaml
govpay.auth.public-chain.permit-all-paths[0].methods[0]=GET
govpay.auth.public-chain.permit-all-paths[1].path=/swagger-ui/**
govpay.auth.public-chain.permit-all-paths[2].path=/swagger-ui.html
govpay.auth.public-chain.permit-all-paths[3].path=/v3/api-docs/swagger-config
govpay.auth.public-chain.permit-all-paths[4].path=/auth/methods
govpay.auth.public-chain.permit-all-paths[4].methods[0]=GET
```

## Configurazione

La libreria non ha un proprio `application.properties`: le proprietà, tutte con prefisso `govpay.auth.`, si impostano nell'applicazione che la usa (`application.properties`, `-D<proprietà>=<valore>` o variabili d'ambiente). La variabile d'ambiente segue le regole di Spring Boot: maiuscole, `.` sostituito da `_` e trattini rimossi, per esempio `GOVPAY_AUTH_BASIC_ENABLED` per `govpay.auth.basic.enabled` e `GOVPAY_AUTH_PUBLICCHAIN_PERMITALLPATHS_0_PATH` per `govpay.auth.public-chain.permit-all-paths[0].path`.

Il jar contiene i metadati delle proprietà (`META-INF/spring-configuration-metadata.json`), usati dagli IDE per il completamento e la documentazione nei file di configurazione dei progetti.

Ogni metodo ha la proprietà `govpay.auth.<metodo>.enabled` (default `false`). Le liste si impostano con valori separati da virgola o con gli indici (`[0]`, `[1]`, ...).

### BASIC e password

| Proprietà | Default | Descrizione |
|-----------|---------|-------------|
| `govpay.auth.basic.enabled` | `false` | Abilita Basic Auth sulle utenze del loader |
| `govpay.auth.password.md5-fallback-enabled` | `true` | Accetta in lettura anche le password MD5 Unix crypt `$1$` oltre alle SHA-512 `$6$`. Da disattivare quando tutte le utenze sono state ricifrate in `$6$` |

### FORM

| Proprietà | Default | Descrizione |
|-----------|---------|-------------|
| `govpay.auth.form.enabled` | `false` | Abilita il login JSON con sessione e CSRF |
| `govpay.auth.form.login-path` | `/auth/login` | Path della `POST` di login |
| `govpay.auth.form.logout-path` | `/auth/logout` | Path della `POST` di logout di sessione (usato anche da `SPID`) |
| `govpay.auth.form.csrf-cookie-name` | `XSRF-TOKEN` | Cookie con il token CSRF (convenzione Angular) |
| `govpay.auth.form.csrf-header-name` | `X-XSRF-TOKEN` | Header con cui il browser rimanda il token CSRF |
| `govpay.auth.form.rate-limit.attempts` | `5` | Tentativi di login falliti ammessi per IP nella finestra |
| `govpay.auth.form.rate-limit.window-minutes` | `15` | Durata in minuti della finestra dei tentativi |

### LDAP

| Proprietà | Default | Descrizione |
|-----------|---------|-------------|
| `govpay.auth.ldap.enabled` | `false` | Abilita la verifica delle credenziali Basic su LDAP |
| `govpay.auth.ldap.url` | - | URL del server, es. `ldap://ldap.example.com:389/dc=example,dc=com`. Obbligatorio: senza, l'avvio fallisce |
| `govpay.auth.ldap.manager-dn` | - | DN per il bind di ricerca; vuoto se l'utente fa il bind diretto |
| `govpay.auth.ldap.manager-password` | - | Password del `manager-dn` |
| `govpay.auth.ldap.user-dn-pattern` | - | Pattern del DN utente per il bind diretto, es. `uid={0},ou=people` |
| `govpay.auth.ldap.user-search-filter` | - | Filtro di ricerca dell'utente, es. `(uid={0})`, in alternativa a `user-dn-pattern` |
| `govpay.auth.ldap.user-search-base` | - | Base della ricerca utenti, es. `ou=people` |
| `govpay.auth.ldap.group-search-base` | vuoto | Base della ricerca dei gruppi, es. `ou=groups` |
| `govpay.auth.ldap.group-search-filter` | `(uniqueMember={0})` | Filtro di ricerca dei gruppi dell'utente |
| `govpay.auth.ldap.password-attribute-name` | `userPassword` | Attributo password nella directory. Non usato: l'autenticazione avviene con il bind dell'utente |
| `govpay.auth.ldap.role-prefix` | `ROLE_` | Prefisso dei ruoli ricavati dai gruppi LDAP e dal loader |
| `govpay.auth.ldap.convert-to-upper-case` | `true` | Converte i ruoli in maiuscolo |

Se il bind LDAP fallisce e `BASIC` è abilitato, la richiesta viene verificata anche con Basic Auth sul loader. Ai ruoli LDAP si aggiungono quelli restituiti dal loader.

### SSL, SSL_HEADER, HEADER, API_KEY, SPID e SESSION

| Proprietà | Default | Descrizione |
|-----------|---------|-------------|
| `govpay.auth.ssl.enabled` | `false` | Abilita il certificato client della connessione TLS (richiede `server.ssl.client-auth` nel container) |
| `govpay.auth.ssl.subject-principal-regex` | `^(.*)$` | Espressione regolare applicata al subject DN; il primo gruppo è il principal (default: tutto il DN) |
| `govpay.auth.ssl-header.enabled` | `false` | Abilita il certificato client inoltrato in un header |
| `govpay.auth.ssl-header.principal-header-name` | `X-SSL-Client-Cert` | Header con il certificato (PEM, eventualmente codificato) |
| `govpay.auth.ssl-header.url-decode` | `false` | Prova la decodifica URL del valore |
| `govpay.auth.ssl-header.base64-decode` | `false` | Prova la decodifica Base64 del valore |
| `govpay.auth.ssl-header.hex-decode` | `false` | Prova la decodifica esadecimale del valore |
| `govpay.auth.ssl-header.replace-characters-enabled` | `false` | Sostituisce caratteri nel corpo del PEM prima della decodifica (es. nginx `$ssl_client_escaped_cert`, che mette tabulazioni al posto degli a capo) |
| `govpay.auth.ssl-header.replace-source` | `\t` se vuoto | Carattere da sostituire; accetta i letterali `\t`, `\r`, `\n`, `\r\n`, `\s` |
| `govpay.auth.ssl-header.replace-dest` | `\n` se vuoto | Carattere sostitutivo; stessi letterali di `replace-source` |
| `govpay.auth.header.enabled` | `false` | Abilita il principal in header |
| `govpay.auth.header.principal-header-names` | `X-Pre-Auth-User` | Header da consultare, in ordine: vale il primo non vuoto |
| `govpay.auth.api-key.enabled` | `false` | Abilita la coppia id/chiave in header |
| `govpay.auth.api-key.id-header-name` | `X-Govpay-API-ID` | Header con l'identificativo (principal) |
| `govpay.auth.api-key.key-header-name` | `X-Govpay-API-Key` | Header con la chiave, verificata come password con `GovpayPasswordEncoder` |
| `govpay.auth.spid.enabled` | `false` | Abilita il principal SPID in header, con sessione |
| `govpay.auth.spid.principal-header-name` | - | Header con il codice fiscale. Obbligatorio: senza, l'avvio fallisce |
| `govpay.auth.spid.tinit-prefix` | `TINIT-` | Prefisso rimosso dal valore per ottenere il codice fiscale; vuoto per non rimuovere nulla |
| `govpay.auth.session.enabled` | `false` | Abilita il principal letto dalla sessione |
| `govpay.auth.session.session-principal-attribute-name` | `GP_PRINCIPAL` | Attributo della `HttpSession` con il principal |

Con `SSL_HEADER` la decodifica, se è attivo almeno uno dei flag, prova nell'ordine URL e Base64, poi esadecimale se `hex-decode=true`; senza flag il valore è letto come PEM. Il principal è il subject DN del certificato in formato RFC 2253. Gli header di `HEADER`, `SSL_HEADER` e `SPID` vanno accettati solo dal proxy: il servizio non deve essere raggiungibile direttamente dai client.

### OAUTH2

| Proprietà | Default | Descrizione |
|-----------|---------|-------------|
| `govpay.auth.oauth2.enabled` | `false` | Abilita i token Bearer JWT |
| `govpay.auth.oauth2.jwk-set-uri` | - | URI del JWK Set dell'IdP. Obbligatorio: senza, l'avvio fallisce |
| `govpay.auth.oauth2.issuer` | vuoto | Valore atteso del claim `iss`; vuoto disattiva il controllo |
| `govpay.auth.oauth2.audience` | vuoto | Valore atteso nel claim `aud`; vuoto disattiva il controllo |
| `govpay.auth.oauth2.principal-claim-name` | `sub` | Claim da cui leggere il principal; accetta un elenco separato da virgola, usato in ordine (es. `preferred_username,sub`) |
| `govpay.auth.oauth2.claim-validation-rules.<claim>` | - | Valori ammessi per un claim aggiuntivo, es. `govpay.auth.oauth2.claim-validation-rules.azp=govpay-console`. I valori vuoti sono ignorati |
| `govpay.auth.oauth2.realm-name` | - | Realm nell'header `WWW-Authenticate: Bearer` delle risposte 401 |
| `govpay.auth.oauth2.logout-uri` | - | URI di logout dell'IdP OIDC |
| `govpay.auth.oauth2.post-logout-redirect-uri` | - | Valore del parametro `post_logout_redirect_uri` |
| `govpay.auth.oauth2.logout-path` | `/auth/oauth2/logout` | Path della `POST` di logout OAuth2, attivo solo con `logout-uri` e `post-logout-redirect-uri` |

Il token è validato su scadenza, `iss`, `aud` e regole dei claim; il principal è poi caricato con il loader (`AuthType.OAUTH2`). I ruoli sono quelli del claim `scope`/`scp` (prefisso `SCOPE_`) più quelli del loader.

### Path pubblici

| Proprietà | Default | Descrizione |
|-----------|---------|-------------|
| `govpay.auth.public-chain.enabled` | `false` | Abilita i path accessibili senza autenticazione |
| `govpay.auth.public-chain.permit-all-paths[n].path` | - | Pattern del path (sintassi `PathPattern` di Spring, es. `/swagger-ui/**`) |
| `govpay.auth.public-chain.permit-all-paths[n].methods` | tutti | Metodi HTTP ammessi senza autenticazione; vuoto vale per tutti |
| `govpay.auth.static-resources.enabled` | `true` | Rende pubbliche le risorse statiche |
| `govpay.auth.static-resources.permit-all-paths` | `/index.html`, `/favicon.ico`, `/*.png`, `/*.css`, `/*.css.map`, `/*.js`, `/*.js.map`, `/webjars/**`, `/static/**` | Pattern delle risorse statiche |

Le richieste `OPTIONS` (preflight CORS) sono sempre pubbliche; tutti gli altri path richiedono l'autenticazione.

### Header di sicurezza e firewall

| Proprietà | Default | Descrizione |
|-----------|---------|-------------|
| `govpay.auth.headers.content-type-options-enabled` | `true` | Header `X-Content-Type-Options: nosniff` |
| `govpay.auth.headers.frame-options-enabled` | `true` | Header `X-Frame-Options: DENY` |
| `govpay.auth.headers.xss-protection-enabled` | `true` | Header `X-XSS-Protection` |
| `govpay.auth.firewall.allow-url-encoded-slash` | `true` | Accetta `%2F` nel path, necessario per gli identificativi pagoPA che contengono `/` |
| `govpay.auth.firewall.allow-url-encoded-percent` | `true` | Accetta `%25` nel path |

### CORS

| Proprietà | Default | Descrizione |
|-----------|---------|-------------|
| `govpay.auth.cors.enabled` | `false` | Registra una `CorsConfigurationSource` (se il progetto non ne ha una propria) e la applica alla catena |
| `govpay.auth.cors.path-pattern` | `/**` | Path su cui applicare la configurazione |
| `govpay.auth.cors.allow-all-origin` | `false` | Ammette qualunque origine |
| `govpay.auth.cors.allow-origins` | vuoto | Origini ammesse, ignorate se `allow-all-origin=true` |
| `govpay.auth.cors.allow-headers` | `*` | Header ammessi nelle richieste |
| `govpay.auth.cors.allow-methods` | `GET,POST,PUT,PATCH,DELETE,OPTIONS` | Metodi ammessi |
| `govpay.auth.cors.expose-headers` | vuoto | Header esposti al browser (`Access-Control-Expose-Headers`) |
| `govpay.auth.cors.allow-credentials` | `false` | `Access-Control-Allow-Credentials` |
| `govpay.auth.cors.max-age-seconds` | `1800` | Durata in secondi della cache del preflight |

## Funzionamento della catena

- **Catena unica con riconoscimento del metodo.** I filtri della libreria (`LDAP`, `FORM`, `API_KEY`, `HEADER`, `SSL_HEADER`, `SPID`, `SESSION`) sono inseriti prima del `BasicAuthenticationFilter`; Basic, X.509 e Bearer sono i filtri standard di Spring Security. Un filtro pre-autenticato non riautentica una richiesta già autenticata da un filtro precedente.
- **Metodo applicato.** `AuthTypeStampingFilter` salva nella richiesta l'`AuthType` effettivo (attributo `it.govpay.common.auth.authType`, letto da `AuthTypeAccessor.current(request)`) e `PrincipalCaptureFilter` il principal (attributo `it.govpay.common.auth.principal`), disponibile anche dopo la pulizia del `SecurityContext`, per esempio nei filtri di log.
- **Sessione.** La sessione è creata solo con `FORM` o `SPID` (al massimo due sessioni contemporanee per utenza, identificativo rigenerato al login); negli altri casi la catena è stateless.
- **CSRF.** Attivo solo con `FORM` o `SPID`, con token nel cookie `XSRF-TOKEN` (leggibile da JavaScript) e header `X-XSRF-TOKEN`. Non è richiesto per la `POST` di login, per le richieste con header `Authorization` e per quelle senza sessione.
- **Errori in `application/problem+json`.** 401 senza autenticazione valida (con `WWW-Authenticate: Bearer` per `OAUTH2`), 403 per accesso negato o token CSRF errato, 401 per sessione scaduta o non valida.
- **Limite dei tentativi di login.** `LoginRateLimiter` conta i tentativi falliti di `POST /auth/login` per IP del chiamante (`request.getRemoteAddr()`) e risponde 429 oltre `rate-limit.attempts` nella finestra; un login riuscito azzera il conteggio. L'header `X-Forwarded-For` non viene letto direttamente, perché il client può impostarlo a piacere e aggirare il limite.

### Dietro un reverse proxy

Senza configurazione, dietro un reverse proxy `getRemoteAddr()` è l'indirizzo del proxy: tutti i client condividono lo stesso conteggio dei tentativi falliti e, superato il limite, nessuno riesce più a fare login per la durata della finestra. Il progetto che usa la libreria deve far leggere a Spring Boot l'IP reale dagli header del proxy, che vengono accettati solo se la richiesta arriva da un proxy fidato:

```properties
server.forward-headers-strategy=native
# Indirizzi dei proxy fidati (espressione regolare). Il default di Tomcat copre
# le reti private (10/8, 192.168/16, 172.16/12, 169.254/16, 127/8); va
# impostato se il proxy ha un indirizzo diverso.
server.tomcat.remoteip.internal-proxies=10\\.0\\.0\\.5
```

Con `native` l'IP è ricavato da `X-Forwarded-For` da Tomcat (`RemoteIpValve`); in alternativa `framework` usa il `ForwardedHeaderFilter` di Spring, che però si fida degli header di qualunque chiamante, quindi va usato solo se il servizio è raggiungibile esclusivamente dal proxy.

## Licenza

GovPay Common Auth è distribuito con licenza [GNU General Public License v3.0](LICENSE).

Copyright (c) 2014-2026 Link.it srl.
