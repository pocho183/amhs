# AMHS – Guida completa di presentazione e comprensione del codice

> Obiettivo di questo documento: darti una traccia solida per presentare il progetto al tuo responsabile con sicurezza, spiegando **architettura, scelte tecniche, flussi end-to-end e ruolo di ogni blocco di codice**.

---

## 1) Cos'è questo progetto in una frase

Questo progetto implementa un server AMHS applicativo in Java/Spring Boot che riceve messaggi su trasporto RFC1006/TLS, valida i dati secondo regole AMHS/X.400 semplificate, persiste messaggi/stati/report e può inoltrare outbound verso altri hop MTA.

---

## 2) Messaggio chiave per il tuo boss (pitch breve)

- Ho costruito un servizio AMHS con stack runtime robusto (Spring Boot + TLS + JPA).
- Ho separato responsabilità in moduli chiari: rete, parsing/protocollo, validazione, persistenza, state machine, relay.
- Ho progettato il sistema per operare sia in modalità database che no-database.
- Ho incluso test automatici per protocolli, parsing BER, routing, conformità e componenti ACSE/P1.

---

## 3) Mappa ad alto livello del codice

## Entry-point e bootstrap
- `it.amhs.AMHS`: avvio applicazione, modalità non-web, override no-DB, creazione SSLContext, start server RFC1006.
- `AMHSBootstrapService`: seed iniziale dei canali AMHS (`ATFM`, `AFTN`) in base alla policy mTLS.

## Networking e protocol stack
- `RFC1006Server`: listener TLS socket su host/porta configurabili.
- `RFC1006Service`: cuore del protocol handling (TPKT/COTP, sessione, parse payload, ACK/NACK, retrieval).
- `CotpConnectionTpdu`, `PresentationContext`, `AcseAssociationProtocol`, `P1AssociationProtocol`: gestione dettagli handshake/sessione ACSE/P1.
- `P1BerMessageParser`, `BerCodec`, `BerTlv`, `X411TagMap`, `ExtensibilityContainers`: BER/X.411 decoding e mapping campi.

## Business e persistenza
- `MTAService`: costruzione messaggio, validazioni, transizioni stato, persistenza.
- `AMHSComplianceValidator`: regole su header AMHS, profili, indirizzi O/R, identity binding certificato.
- `AMHSMessageStateMachine`: lifecycle coerente (`SUBMITTED -> TRANSFERRED -> DELIVERED -> REPORTED` etc.).
- `AMHSDeliveryReportService`: gestione report di consegna/non-consegna.
- Repository JPA: `AMHSMessageRepository`, `AMHSChannelRepository`, `AMHSDeliveryReportRepository`.

## Relay outbound
- `RelayRoutingService`: risoluzione next-hop da routing table.
- `OutboundRelayEngine`: scheduler retry/backoff/dead-letter.
- `OutboundP1Client` / `Rfc1006OutboundP1Client`: trasmissione outbound verso nodo remoto.

## Domini e modelli
- `AMHSMessage`, `AMHSChannel`, `AMHSDeliveryReport` + enum (`AMHSProfile`, `AMHSPriority`, `AMHSMessageState`, ecc.).

---

## 4) Scelte architetturali e perché sono corrette

1. **Spring Boot non-web (`WebApplicationType.NONE`)**
   - Scelta coerente: questo non è un servizio REST ma un server socket/protocollo.
   - Riduce superficie inutile (niente web stack superfluo).

2. **TLS nativo con `SSLContext` centralizzato**
   - Tutta la policy crittografica è in un factory dedicato.
   - Consente mTLS e controlli PKIX configurabili.

3. **Separazione trasporto vs dominio**
   - `RFC1006Service` gestisce framing/protocollo.
   - `MTAService` gestisce regole di dominio e persistenza.
   - Beneficio: testabilità, manutenzione, minor accoppiamento.

4. **State machine esplicita**
   - Evita inconsistenze sul lifecycle messaggio.
   - Permette auditing e troubleshooting più semplice.

5. **Modalità DB opzionale**
   - Ottima per demo/lab/smoke test senza dipendere da un database sempre disponibile.

6. **Relay con retry esponenziale + dead-letter**
   - Pattern enterprise standard per robustezza operativa.
   - Controlla failure transitorie senza perdere tracciabilità.

---

## 5) Flusso end-to-end (dalla connessione al messaggio archiviato)

1. Avvio applicazione (`AMHS.main`)
   - Carica configurazione.
   - Eventualmente applica override no-DB.
   - Crea `SSLContext`.
   - Avvia listener RFC1006 in thread dedicato.

2. Connessione client su TLS
   - `RFC1006Server` accetta socket e delega a `RFC1006Service.handleClient`.

3. Gestione frame RFC1006/TPKT/COTP
   - Lettura header frame.
   - Validazione lunghezze, tipo TPDU, segmentazione EOT.
   - Gestione TPDU di connessione/disconnessione/errori.

4. Handshake applicativo
   - Se payload sembra ACSE/P1, viene decodificato e validato.
   - Verifica application-context OID, presentation context, AE-title e auth-value.

5. Parsing messaggio
   - Path testuale AMHS (header `From/To/Subject/...`) oppure path BER/P1 transfer.

6. Validazione business
   - Verifica sintassi/profilo/priorità.
   - Verifica canale abilitato.
   - Verifica vincoli certificato (`CN/OU`) e binding O/R.

7. Persistenza + stati + report
   - Inizializzazione stato.
   - Transizioni stato con salvataggi progressivi.
   - Creazione delivery report (successo/fallimento).

8. Risposta al peer
   - ACK (`Status: RECEIVED`) o NACK (`Status: REJECTED` + motivazione).

9. (Opzionale) Relay outbound schedulato
   - Scanner messaggi pending/deferred.
   - Routing next-hop.
   - Invio e aggiornamento trace/retry/dead-letter.

---

## 6) Walkthrough “riga per riga” dei punti più critici

> Nota realistica: spiegare **letteralmente ogni riga dell'intero repository** in un singolo documento lo renderebbe poco fruibile. Qui trovi una spiegazione quasi line-by-line dei file che governano il comportamento core; per il resto, hai una mappa file-per-file più sotto.

### 6.1 `AMHS.java` (bootstrap)
- Campi `@Value`: estraggono parametri runtime (porta, keystore, truststore, policy).
- `main`: inizializza Spring, disabilita modalità web, applica initializer config, esegue app.
- `configureDatabaseMode`: se DB off, esclude auto-config JPA/JDBC e disabilita scheduler.
- Bean `sslContext`: usa `TLSContextFactory` per creare il contesto TLS.
- `parsePolicyOids`: converte CSV in `Set<String>` pulito.
- Bean `startServer`: avvia server RFC1006 in thread separato.

### 6.2 `RFC1006Server.java` (listener)
- Costruttore: riceve host/porta, flag client-auth, `SSLContext`, service handler.
- `start()`:
  1. crea `SSLServerSocket` bindato,
  2. imposta TLSv1.2/TLSv1.3,
  3. applica `needClientAuth`,
  4. loop infinito `accept()`,
  5. ogni socket va su thread dedicato con `handleClient`.

### 6.3 `RFC1006Service.java` (cuore protocollo)
- Costanti: codici TPKT/COTP, limiti frame, OID AMHS P1.
- Dipendenze: repository, `MTAService`, parser BER, protocolli P1/ACSE.
- `handleClient`:
  - set timeout,
  - estrae identità cert peer,
  - legge frame in loop,
  - gestisce CR/DR/ER/ED/DT,
  - ricompone payload segmentati,
  - instrada tra handshake P1/ACSE, retrieval o submit messaggio,
  - invia ACK/NACK.
- `validateAarqForAmhsP1`: enforcement rigoroso per ACSE AARQ.
- `readFramedPayload`: parser robusto TPKT/COTP con controlli di sicurezza su lunghezze.
- parser utility (`parseHeaders`, `parseProfile`, `parsePriority`, `parseFilingTime`) normalizzano input.

### 6.4 `MTAService.java` (dominio + persistenza)
- `storeMessage` / `storeX400Message`: creano oggetto base e differenziano campi extra X.400.
- In modalità DB off: logga e ritorna senza persistere.
- In modalità DB on:
  1. valida conformità,
  2. valida canale/policy cert,
  3. aggiorna stato,
  4. salva,
  5. genera report,
  6. gestisce failure con stato `FAILED` + non-delivery report.

### 6.5 `OutboundRelayEngine.java` (resilienza outbound)
- Scheduler periodico (`@Scheduled`) su messaggi `SUBMITTED/DEFERRED`.
- `relaySingle`:
  - loop detection su trace,
  - route lookup,
  - tentativo trasferimento,
  - aggiorna outcome/stato o retry con backoff esponenziale,
  - dead-letter a fine tentativi o mancanza route.

---

## 7) Mappa sintetica file-per-file (utile in presentazione)

- `api/`: DTO input (`ChannelRequest`, `X400MessageRequest`).
- `asn1/`: utility BER low-level.
- `compliance/`: regole formali di validazione AMHS/X.400.
- `config/`: wiring alternativo quando DB è disabilitato.
- `domain/`: entity JPA + enum di stato/profilo/priorità.
- `network/`: socket server layer.
- `repository/`: query persistence.
- `security/`: creazione e policy TLS.
- `service/`: orchestrazione business/protocol.
- `test/`: client di prova manuale.

---

## 8) Decisioni implementative “da raccontare bene”

1. **Normalizzazione input (`trim`, uppercase per codici)**
   - Previene mismatch su channel/profile/identificatori.

2. **Default sensati (`GG`, `P3`, channel `ATFM`)**
   - Migliora robustezza operativa e riduce reject inutili.

3. **Controlli difensivi su frame lengths**
   - Mitiga payload malformati o attacchi banali di framing.

4. **Log operativi su eventi chiave**
   - Favorisce audit trail e incident analysis.

5. **No-DB mode con override Spring**
   - Permette esecuzioni in ambienti ridotti senza riscrivere codice business.

---

## 9) Come “dimostrare” rapidamente che funziona

1. Build:
```bash
./gradlew classes
```

2. Avvio server:
```bash
./gradlew bootRun
```

3. Invio messaggio con client di test:
```bash
java -cp build/classes/java/main it.amhs.test.AMHSTestClient --channel ATFM --count 1
```

4. Retrieval:
```bash
java -cp build/classes/java/main it.amhs.test.AMHSTestClient --retrieve-all
```

5. Test automatici:
```bash
./gradlew test
```

---

## 10) Limiti attuali da comunicare con trasparenza

- Il progetto è molto avanzato lato simulazione applicativa e relay, ma non sostituisce automaticamente un prodotto AMHS già certificato ICAO end-to-end.
- In contesti di certificazione formale servono campagne di interoperabilità, evidenze e allineamento completo ai profili richiesti dal laboratorio.

---

## 11) Piano miglioramento (se il boss chiede “next steps”)

- Migliorare osservabilità (metriche Micrometer/Prometheus su TPDU, reject reason, retry).
- Rafforzare test di interoperabilità con nodi esterni reali.
- Hardening sicurezza (rotazione certificati, pinning policy, alerting su handshake failure).
- Dashboard operativa su stato code relay e dead-letter.

---

## 12) Script verbale pronto per te (1 minuto)

"Ho realizzato un server AMHS su Java 21 e Spring Boot orientato al trasporto RFC1006 su TLS. Ho separato chiaramente il livello protocollo dal dominio AMHS: il primo gestisce handshake e frame TPKT/COTP/ACSE/P1, il secondo applica regole di compliance, stato lifecycle e persistenza. Ho inserito validazioni certificate-bound su canale e O/R address, più una pipeline di relay outbound con retry esponenziale e dead-letter. Il codice è testato con suite unitarie sui moduli critici, ed è pronto sia per ambienti con database sia per modalità no-DB di laboratorio." 

---

## 13) Come usare questo documento per studiare il codice

- Prima leggi sezioni 3, 4 e 5 per visione d'insieme.
- Poi apri i file indicati in sezione 6 e segui il flusso da bootstrap a persistenza.
- Infine usa sezione 7 come checklist per non perdere nessun pacchetto.

Se vuoi, nel prossimo passo posso prepararti anche una **versione “parlata” slide-by-slide** (10 slide) pronta da usare in riunione.
