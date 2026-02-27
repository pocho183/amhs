# AMHS Server - Guida operativa pronta all'uso

Questa guida è pensata per portare il server AMHS in esercizio rapidamente, con esempi pratici per:

- avvio servizio,
- gestione canali (`Channel`) con policy certificato (`CN`/`OU`),
- invio/ricezione messaggi via REST,
- invio/ricezione messaggi via RFC1006/TLS,
- checklist di deploy pre-produzione.

---

## 1) Prerequisiti

- Java 17+ installato.
- PostgreSQL raggiungibile dal server.
- Porta RFC1006 aperta (default: `102`).
- Certificati TLS presenti in `src/main/resources/certs` (keystore server e truststore client).

Configurazione base predefinita in `application.properties`:

- DB: `jdbc:postgresql://localhost:5432/amhs`
- RFC1006: `rfc1006.server.port=102`
- mTLS: `rfc1006.tls.need-client-auth=true`
- Keystore: `tls.keystore.path=classpath:certs/server.p12`
- Truststore: `tls.truststore.path=classpath:certs/client-truststore.jks`

---

## 2) Avvio rapido

### 2.1 Avvio applicazione

```bash
./gradlew bootRun
```

### 2.2 Verifica health

```bash
curl -s http://localhost:8080/api/amhs/messages/health
```

Output atteso:

```text
AMHS server running
```

> Nota: all'avvio viene creato automaticamente il canale `DEFAULT` abilitato.

---

## 3) Gestione canali (CN/OU policy)

I canali governano la policy di accettazione lato MTA:

- `name`: nome canale (es. `AFTN`, `ATFM`, `DEFAULT`)
- `expectedCn`: CN richiesto dal certificato client (opzionale)
- `expectedOu`: OU richiesto dal certificato client (opzionale)
- `enabled`: abilitazione canale

### 3.1 Creare/aggiornare un canale con vincolo CN+OU

```bash
curl -s -X POST http://localhost:8080/api/amhs/channels \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "ATFM",
    "expectedCn": "amhs-client-01",
    "expectedOu": "ATM",
    "enabled": true
  }'
```

### 3.2 Elencare i canali

```bash
curl -s http://localhost:8080/api/amhs/channels
```

### 3.3 Disabilitare un canale

```bash
curl -s -X POST http://localhost:8080/api/amhs/channels \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "ATFM",
    "expectedCn": "amhs-client-01",
    "expectedOu": "ATM",
    "enabled": false
  }'
```

---

## 4) Invio messaggi via REST

## Requisiti payload AMHS

- `from` / `to`: formato OR-address short (8 caratteri alfanumerici maiuscoli).
- `profile`: uno tra `P1`, `P3`, `P7`.
- `priority`: una priorità supportata (es. `GG`, `FF`, `DD`, `SS`).
- `channel`: canale esistente e abilitato.

### 4.1 Invio messaggio REST

```bash
curl -s -X POST http://localhost:8080/api/amhs/messages \
  -H 'Content-Type: application/json' \
  -d '{
    "messageId": "MSG-ATFM-0001",
    "from": "LIRRAAAA",
    "to": "LIRRBBBB",
    "body": "ATFM SLOT REVISION FOR FLIGHT AZ123",
    "channel": "ATFM",
    "profile": "P3",
    "priority": "GG",
    "subject": "ATFM UPDATE"
  }'
```

### 4.2 Lista messaggi ricevuti

```bash
curl -s http://localhost:8080/api/amhs/messages
```

### 4.3 Lista messaggi filtrati (channel/profile)

```bash
curl -s "http://localhost:8080/api/amhs/messages?channel=ATFM&profile=P3"
```

### 4.4 Capabilities

```bash
curl -s http://localhost:8080/api/amhs/messages/capabilities
```

---

## 4-bis) Submit messaggi X.400/P3 (stile Isode)

Per registrare metadati P3/X.400 (OR-address mittente/destinatario, presentation address, IPN/DR, timeout DR), usare endpoint dedicato:

```bash
curl -s -X POST http://localhost:8080/api/amhs/messages/x400 \
  -H 'Content-Type: application/json' \
  -d '{
    "messageId": "MSG-P3-0001",
    "body": "(FPL-AZA123-IS ...)",
    "p3Subject": "FLIGHT PLAN",
    "priority": "GG",
    "ipnRequest": 1,
    "deliveryReport": "DR_YES",
    "timeoutDr": 30000,
    "p3ProtocolIndex": "1006",
    "p3ProtocolAddress": "tcp",
    "p3ServerAddress": "10.10.10.20",
    "p3CommonName": "amhs-originator",
    "p3OrganizationUnit": "ATM",
    "p3OrganizationName": "ENAV",
    "p3PrivateManagementDomain": "AFTN",
    "p3AdministrationManagementDomain": "ICAO",
    "p3CountryName": "IT",
    "p3CommonNameRecipient": "amhs-destination",
    "p3OrganizationUnitRecipient": "AIM",
    "p3OrganizationNameRecipient": "ENAV",
    "p3PrivateManagementDomainRecipient": "AFTN",
    "p3AdministrationManagementDomainRecipient": "ICAO",
    "p3CountryNameRecipient": "IT",
    "channel": "ATFM",
    "certificateCn": "amhs-client-01",
    "certificateOu": "ATM"
  }'
```

## 5) Invio/Retrieval via RFC1006 su TLS

Il server usa frame con:

1. 2 byte iniziali (`short`) = lunghezza payload UTF-8,
2. payload testuale con header stile:

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

Comandi retrieval supportati nel payload:

- `RETRIEVE ALL`
- `RETRIEVE <MESSAGE_ID>`

### 5.1 Client di esempio Python (TLS + lunghezza 2 byte)

```python
import socket
import ssl

HOST = "127.0.0.1"
PORT = 102

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="src/main/resources/certs/server.crt")
context.load_cert_chain(certfile="client.crt", keyfile="client.key")

payload = """Message-ID: MSG-RFC-0001
From: LIRRAAAA
To: LIRRBBBB
Profile: P3
Priority: GG
Channel: ATFM
Subject: TEST RFC1006
Body: THIS IS A RFC1006 AMHS MESSAGE
""".encode("utf-8")

packet = len(payload).to_bytes(2, byteorder="big") + payload

with socket.create_connection((HOST, PORT)) as tcp:
    with context.wrap_socket(tcp, server_hostname="amhs.local") as tls:
        tls.sendall(packet)

        # ricezione ACK
        size = int.from_bytes(tls.recv(2), byteorder="big")
        ack = tls.recv(size).decode("utf-8", errors="replace")
        print("ACK:\n", ack)
```

### 5.2 Retrieval via RFC1006 (stesso framing)

Payload da inviare:

```text
RETRIEVE ALL
```

oppure:

```text
RETRIEVE MSG-RFC-0001
```

---

## 6) Certificati (CN/OU) - flusso operativo

Nel repository sono presenti esempi comando per:

- generare `server.p12` (`crea.certificato.server.p12.txt`),
- esportare certificato server e creare truststore client (`crea.certificato.client.p12.txt`).

Flusso consigliato:

1. Genera certificato server con `CN` coerente al DNS/FQDN reale.
2. Distribuisci la CA/cert server ai client AMHS.
3. Crea certificato client con `CN`/`OU` coerenti alla policy canale.
4. Importa la CA/cert client nel truststore server (`client-truststore.jks`).
5. Configura canale con gli stessi valori `expectedCn`/`expectedOu`.

---

## 7) Checklist deploy (pre-produzione)

## Sicurezza e PKI

- [ ] Password di default (`changeit`) sostituite in keystore/truststore e datasource.
- [ ] Certificati non self-signed in produzione (CA interna/autorità qualificata).
- [ ] `CN`/`OU` client allineati alle policy dei canali AMHS.
- [ ] Rotazione periodica certificati e piano revoca/CRL/OCSP.

## Rete e hardening

- [ ] Porta 102 esposta solo a peer autorizzati.
- [ ] Firewall e ACL configurati.
- [ ] Logging centralizzato e retention conforme policy operativa.

## Applicazione e DB

- [ ] DB PostgreSQL con backup, restore testato e monitoraggio.
- [ ] Parametri `application.properties` esternalizzati (env/secret manager).
- [ ] Verifica endpoint `/health`, `/capabilities`, `/channels`, `/messages`.

## Esercizio operativo

- [ ] Test end-to-end REST (submit/list).
- [ ] Test end-to-end RFC1006 TLS (submit/retrieve).
- [ ] Test negativi (canale disabilitato, CN mismatch, OU mismatch).
- [ ] Piano di capacity/performance e sizing thread/connessioni.

## Compliance ICAO (nota)

- [ ] Conformance testing ufficiale (P1/P3/P7) pianificato con ente/lab accreditato.
- [ ] Evidenze operative, security governance e processi regolatori documentati.

---

## 8) Comandi rapidi utili

### Leggere capacità server

```bash
curl -s http://localhost:8080/api/amhs/messages/capabilities | jq .
```

### Leggere ultimi messaggi

```bash
curl -s http://localhost:8080/api/amhs/messages | jq .
```

### Leggere canali

```bash
curl -s http://localhost:8080/api/amhs/channels | jq .
```
