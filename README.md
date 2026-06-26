<p align="center">
<img src="https://www.link.it/wp-content/uploads/2025/01/logo-govpay.svg" alt="GovPay Logo" width="200"/>
</p>

# GovPay Common Auth

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://raw.githubusercontent.com/link-it/govpay-common-auth/main/LICENSE)

Libreria di autenticazione/autorizzazione per API di GovPay. È una libreria Spring
Boot **auto-configurata**: una volta aggiunta al classpath registra una
**filter chain di sicurezza unica** che supporta tutti i metodi di autenticazione
di GovPay, lasciando al consumer solo l'implementazione di una SPI minimale per
risolvere il principal sul proprio data layer e l'abilitazione dei metodi via property.

## Requisiti

- Spring Boot 4 / Spring Security 7 (allineati al parent `govpay-bom`)
- Un servlet container (la dipendenza `jakarta.servlet-api` è `provided`: la porta il consumer)
- Un `ObjectMapper` Jackson sul context (presente in qualsiasi app Spring Boot web)

## Coordinate Maven

```xml
<dependency>
    <groupId>org.gov4j.govpay</groupId>
    <artifactId>govpay-common-auth</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

## Metodi di autenticazione supportati

Ogni metodo è disabilitato di default e si attiva con `govpay.auth.<metodo>.enabled=true`.
I codici corrispondono ai valori `AuthType` sono stabili verso l'esterno
(esposti in `Profilo.autenticazione` e in `GET /auth/methods` del consumer).

| `AuthType`   | Property prefix              | Credenziale                                              |
|--------------|------------------------------|----------------------------------------------------------|
| `BASIC`      | `govpay.auth.basic`          | Basic Auth (username/password) verificata localmente     |
| `LDAP`       | `govpay.auth.ldap`           | Basic Auth verificata su server LDAP esterno             |
| `FORM`       | `govpay.auth.form`           | Login JSON `POST /auth/login` + sessione + CSRF cookie    |
| `SSL`        | `govpay.auth.ssl`            | mTLS, certificato client X.509 nativo                    |
| `SSL_HEADER` | `govpay.auth.ssl-header`     | Certificato client inoltrato via header da reverse proxy |
| `HEADER`     | `govpay.auth.header`         | Principal in header HTTP (pre-auth da proxy)             |
| `API_KEY`    | `govpay.auth.api-key`        | Coppia id/key in header                                  |
| `SPID`       | `govpay.auth.spid`           | Principal SPID in header (IdP/shibboleth upstream)       |
| `SESSION`    | `govpay.auth.session`        | Principal da attributo di `HttpSession`                  |
| `OAUTH2`     | `govpay.auth.oauth2`         | Bearer token JWT (resource server)                       |
| `PUBLIC`     | `govpay.auth.public-chain`   | Path in permitAll (anonymous)                            |

I metodi attivi convivono nella stessa chain: la libreria **rileva automaticamente**
quale applicare in base alla request (header/credenziali presenti).

## Quick start

### 1. Implementa la SPI obbligatoria `GovpayPrincipalLoader`

È l'unico punto di contatto con il data layer del consumer: dato un `principal` (e
l'`AuthType` applicato dalla chain), restituisce un `AuthenticatedSubject` con
password hash, flag di abilitazione e ruoli. Restituire `null` se l'utenza non esiste
(la libreria mappa il caso su 401).

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

Il `passwordHash` deve essere verificabile da `GovpayPasswordEncoder` (SHA-512 Unix
crypt `$6$`, con fallback opzionale MD5 `$1$`). Per i metodi senza password (SSL, SPID,
HEADER, ...) il campo può essere `null`. Il prefisso `ROLE_` viene aggiunto dalla
libreria se mancante.

### 2. Abilita i metodi via property

```properties
govpay.auth.basic.enabled=true
govpay.auth.form.enabled=true
```

Tutto il resto (filter chain, entry point/handler `application/problem+json`,
password encoder, CSRF cookie per la FORM, rate limiter sul login) viene configurato
dall'auto-configuration. Nessuna `@Configuration` di sicurezza richiesta lato consumer.

## SPI

| SPI                                | Obbligatoria | Default se assente                                                              |
|------------------------------------|:------------:|---------------------------------------------------------------------------------|
| `GovpayPrincipalLoader`            | **Sì**       | —                                                                               |
| `JsonLoginResponseWriter`          | No           | `DefaultJsonLoginResponseWriter` → `{"principal":"...","autenticazione":"FORM"}` |
| `AuthEventListener`                | No           | no-op (nessun audit/metrica)                                                    |
| `AuthenticationDetailsContributor` | No           | `DefaultAuthenticationDetailsContributor` (delega a Spring)                     |

- **`JsonLoginResponseWriter`** — personalizza il body della risposta di
  `POST /auth/login` (tipicamente il `Profilo` applicativo con ACL/domini).
- **`AuthEventListener`** — riceve `onLoginSuccess` / `onLoginFailed` / `onLogout`
  per inoltrarli al proprio audit (tutti i metodi hanno default no-op).
- **`AuthenticationDetailsContributor`** — popola `Authentication.getDetails()` con
  attributi custom (header tracciati, IP, attributi SPID).

## Endpoint esposti dalla libreria

| Endpoint                | Metodo | Attivo quando         | Descrizione                                          |
|-------------------------|--------|-----------------------|------------------------------------------------------|
| `/auth/login`           | POST   | `form.enabled=true`   | Login JSON `{username, password}`; risposta via SPI  |
| `/auth/logout`          | POST   | sempre (chain unica)  | Invalida la sessione; condiviso da tutti i metodi    |
| `/auth/oauth2/logout`   | POST   | `oauth2.enabled=true` | Logout OIDC verso l'IdP (se `logout-uri` configurato) |

I path di login/logout sono configurabili (`govpay.auth.form.login-path`,
`govpay.auth.form.logout-path`, `govpay.auth.oauth2.logout-path`).

> `GET /auth/methods` **non** è fornito dalla libreria: è un endpoint applicativo del
> consumer (espone i metodi attivi al frontend).

## Configurazione

Tutte le property hanno prefisso `govpay.auth.*`. Sotto i blocchi principali; ogni
metodo accetta come minimo `enabled`.

### FORM

| Property                         | Default        | Note                                    |
|----------------------------------|----------------|-----------------------------------------|
| `form.login-path`                | `/auth/login`  |                                         |
| `form.logout-path`               | `/auth/logout` |                                         |
| `form.csrf-cookie-name`          | `XSRF-TOKEN`   | allineato Angular                       |
| `form.csrf-header-name`          | `X-XSRF-TOKEN` |                                         |
| `form.rate-limit.attempts`       | `5`            | tentativi falliti per IP nella finestra |
| `form.rate-limit.window-minutes` | `15`           |                                         |

### LDAP

`ldap.url`, `ldap.manager-dn`, `ldap.manager-password`, `ldap.user-dn-pattern`,
`ldap.user-search-filter`, `ldap.user-search-base`, `ldap.group-search-base`,
`ldap.group-search-filter` (def. `(uniqueMember={0})`), `ldap.password-attribute-name`
(def. `userPassword`), `ldap.role-prefix` (def. `ROLE_`), `ldap.convert-to-upper-case`
(def. `true`).

### OAUTH2

`oauth2.jwk-set-uri` (obbligatorio se abilitato), `oauth2.issuer`, `oauth2.audience`,
`oauth2.principal-claim-name` (def. `sub`, supporta CSV per fallback),
`oauth2.claim-validation-rules` (mappa claim → valori ammessi), `oauth2.realm-name`,
`oauth2.logout-uri`, `oauth2.post-logout-redirect-uri`, `oauth2.logout-path`.

### SSL / SSL_HEADER / HEADER / API_KEY / SPID / SESSION

- `ssl.subject-principal-regex` (def. `^(.*)$`)
- `ssl-header.principal-header-name` (def. `X-SSL-Client-Cert`), più
  `url-decode` / `base64-decode` / `hex-decode` / `replace-characters-enabled` /
  `replace-source` / `replace-dest` per il decoding del PEM inoltrato dal proxy
- `header.principal-header-names` (lista, def. `[X-Pre-Auth-User]`)
- `api-key.id-header-name` (def. `X-Govpay-API-ID`), `api-key.key-header-name`
  (def. `X-Govpay-API-Key`)
- `spid.principal-header-name` (obbligatorio se abilitato), `spid.tinit-prefix`
  (def. `TINIT-`)
- `session.session-principal-attribute-name` (def. `GP_PRINCIPAL`)

### PUBLIC (permitAll)

Path esentati dall'`authenticated()` globale. Ogni regola ha `path` e opzionalmente
`methods` (vuoto = tutti i verbi).

```properties
govpay.auth.public-chain.enabled=true
govpay.auth.public-chain.permit-all-paths[0].path=/openapi/openapi.yaml
govpay.auth.public-chain.permit-all-paths[0].methods[0]=GET
govpay.auth.public-chain.permit-all-paths[1].path=/swagger-ui/**
```

### Trasversali

| Blocco                                                          | Default         | Note                                                                                                                     |
|-----------------------------------------------------------------|-----------------|------------------------------------------------------------------------------------------------------------------------|
| `password.md5-fallback-enabled`                                 | `true`          | accetta in lettura le password legacy `$1$` (MD5) oltre a `$6$`                                                         |
| `headers.*`                                                     | tutti `true`    | `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection` (V1 li disabilitava: impostare a `false` per replica V1) |
| `firewall.allow-url-encoded-slash` / `allow-url-encoded-percent` | `true`          | necessari per gli identificativi pagoPA con `/` (`%2F`) nei path                                                        |
| `cors.*`                                                        | `enabled=false` | `CorsConfigurationSource` nativo Spring (sostituisce `OriginFilter` V1)                                                 |
| `static-resources.*`                                            | `enabled=true`  | permitAll di `index.html`, `*.css`, `*.js`, `/webjars/**`, ...                                                          |

## Esempio di configurazione (govpay-console-api)

```properties
# Metodi attivi
govpay.auth.basic.enabled=true
govpay.auth.form.enabled=true

# Path pubblici (documentazione OpenAPI + endpoint metodi)
govpay.auth.public-chain.enabled=true
govpay.auth.public-chain.permit-all-paths[0].path=/openapi/openapi.yaml
govpay.auth.public-chain.permit-all-paths[0].methods[0]=GET
govpay.auth.public-chain.permit-all-paths[1].path=/swagger-ui/**
govpay.auth.public-chain.permit-all-paths[2].path=/swagger-ui.html
govpay.auth.public-chain.permit-all-paths[3].path=/v3/api-docs/swagger-config
govpay.auth.public-chain.permit-all-paths[4].path=/auth/methods
govpay.auth.public-chain.permit-all-paths[4].methods[0]=GET
```

## Note di design

- **Chain unica con auto-detect**: a differenza di V1 (una chain per path/metodo), V2
  usa un'unica `SecurityFilterChain` che riconosce il metodo dalla request. I metodi
  pre-auth seguono una precedenza first-wins; BasicAuth è valutato eagerly.
- **`application/problem+json` ovunque**: 401/403, sessione scaduta/invalida e CSRF
  failure producono un Problem Detail RFC 9457 parlante, non i messaggi di default del
  framework.
- **CSRF a cookie** (`XSRF-TOKEN`) per la FORM, allineato al pattern SPA Angular.
- **Auto-configuration** registrate in
  `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`:
  `GovpayAuthAutoConfiguration` (SPI default, password encoder) e
  `GovpaySecurityFilterChainAutoConfiguration` (la chain). Tutto è condizionato sui
  flag `govpay.auth.*`, quindi sovrascrivibile dal consumer.

## Licenza

Vedi [LICENSE](LICENSE).
