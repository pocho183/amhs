# AMHS Server - Guida operativa (modalità non-web)

Questa guida è allineata all'implementazione attuale: il servizio gira **senza API REST** ed espone solo endpoint RFC1006 su TLS.

---

## 1) Architettura runtime attuale

- L'applicazione Spring Boot parte in modalità **non-web** (`WebApplicationType.NONE`).
- Non c'è listener HTTP su `:8080`.
- Il server AMHS è in ascolto su RFC1006/TLS (`rfc1006.server.port`, default `102`).
- Il campo `Channel` è una proprietà del messaggio AMHS (routing/policy), **non** una porta di ascolto.

In pratica:
- **Listening endpoint server**: `host:102` (o porta configurata)
- **Channel AMHS**: header applicativo (`Channel: ATFM`, `Channel: AFTN`, ...)

---

## 2) Configurazione base (`application.properties`)

Parametri principali:

- `rfc1006.server.port=102`
- `rfc1006.tls.need-client-auth=false|true`
- `tls.keystore.path=classpath:certs/server.p12`
- `tls.keystore.password=...`
- `tls.truststore.path=classpath:certs/client-truststore.jks`
- `tls.truststore.password=...`

Nota operativa:
- con `rfc1006.tls.need-client-auth=false` il client può connettersi senza certificato client;
- con `rfc1006.tls.need-client-auth=true` il client deve presentare un certificato valido per la trust chain del server.

---

## 3) Canali seedati all'avvio

All'avvio vengono creati i canali:

- `ATFM` (default)
- `AFTN`

I seed attuali non impongono CN/OU obbligatori, così funzionano anche in modalità non-mTLS.

---

## 4) Formato messaggio RFC1006

Frame richiesto:
1. 2 byte iniziali (big-endian) con lunghezza payload
2. payload UTF-8 con header testuali

Esempio payload:

```text
Message-ID: MSG-RFC-0001
From: LIRRAAAA
To: LIRRBBBB
Profile: P3
Priority: GG
Channel: ATFM
Subject: TEST RFC1006
Body: THIS IS A RFC1006 AMHS MESSAGE
```

Comandi retrieval supportati:
- `RETRIEVE ALL`
- `RETRIEVE <MESSAGE_ID>`

---

## 5) Test rapido con client Java incluso

```bash
# build
./gradlew classes

# invio 1 messaggio su ATFM
java -cp build/classes/java/main it.amhs.test.AMHSTestClient --channel ATFM --count 1

# retrieval
java -cp build/classes/java/main it.amhs.test.AMHSTestClient --retrieve-all
```

---

## 6) mTLS e errore "Certificate CN does not match channel policy"

Se ricevi:

```text
Status: REJECTED
Error: Certificate CN does not match channel policy
```

significa che:
1. il server ha letto il certificato client (o una policy canale CN/OU è configurata),
2. il `Channel` del messaggio punta a un canale la cui policy `expectedCn`/`expectedOu` non combacia con DN del certificato client.

### Cosa verificare

1. **Quale canale stai usando nel payload**
   - es. `Channel: ATFM`.
2. **Policy del canale nel DB** (`amhs_channel`)
   - colonne: `name`, `expected_cn`, `expected_ou`, `enabled`.
3. **Subject del certificato client**
   - verifica CN/OU reali del cert usato dal client.

### Query utili (PostgreSQL)

```sql
SELECT id, name, expected_cn, expected_ou, enabled
FROM amhs_channel
ORDER BY name;
```

Se vuoi testare velocemente con mTLS attivo senza blocchi di policy, puoi azzerare i vincoli CN/OU del canale:

```sql
UPDATE amhs_channel
SET expected_cn = NULL,
    expected_ou = NULL,
    enabled = TRUE
WHERE name = 'ATFM';
```

Se invece vuoi enforcement stretto, imposta valori coerenti col certificato client:

```sql
UPDATE amhs_channel
SET expected_cn = 'amhs-client-01',
    expected_ou = 'ATM',
    enabled = TRUE
WHERE name = 'ATFM';
```

---

## 7) Checklist pre-produzione

- TLS server certificate valido e ruotato.
- Truststore client governance (CA interne/esterne).
- `rfc1006.tls.need-client-auth=true` in ambienti operativi.
- Policy canali (`expected_cn` / `expected_ou`) allineate ai certificati autorizzati.
- Audit DB su messaggi e controlli periodici di retention.
