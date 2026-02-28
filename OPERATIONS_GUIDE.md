# AMHS Server - Guida operativa (modalità non-web)

Questa guida è allineata all'implementazione attuale: il servizio gira **senza API REST** ed espone solo endpoint RFC1006 su TLS.

> ⚠️ **Importante**: questa implementazione è un **simulatore AMHS applicativo** (header testuali + policy AMHS). Non implementa uno stack X.400/P1/P3 ASN.1 completo conforme ICAO Doc 9880/9705 end-to-end.

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

```text
AMHS server running
```

> Nota: all'avvio vengono creati automaticamente i canali `ATFM` (default) e `AFTN` abilitati.

---

## 3) Canali seedati all'avvio

All'avvio vengono creati i canali:

- `name`: nome canale (es. `AFTN`, `ATFM`)
- `expectedCn`: CN richiesto dal certificato client (opzionale)
- `expectedOu`: OU richiesto dal certificato client (opzionale)
- `enabled`: abilitazione canale

I seed attuali non impongono CN/OU obbligatori, così funzionano anche in modalità non-mTLS.

---

## 4) Formato messaggio RFC1006

Frame richiesto:
1. **TPKT** (4 byte): versione `0x03`, reserved `0x00`, lunghezza totale (big-endian)
2. **COTP Data TPDU** (3 byte): `0x02 0xF0 0x80`
3. payload UTF-8 con header testuali

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

Opzioni principali:

- `--channel <name>` (es. `ATFM`, `AFTN`)
- `--from`, `--to`, `--profile`, `--priority`
- `--host`, `--port`, `--truststore`, `--truststore-password`
- `--connect-timeout-ms`, `--read-timeout-ms`
- `--negative-suite` (invalid profile / frame corrotto / oversized)
- `--concurrency <n>` (test concorrente happy-path)

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
