# LanPipe — Technical Route

Working name `LanPipe`, replaceable. Status: draft 2, 2026-09-14, **still current as a
design document** — the decisions below are what the code implements. For the *state of the
build* (what is finished, what is verified, what is not) see `README.md` and
`docs/handover.md`; §9's table now carries a status column. Supersedes draft 1
(`TECHNICAL_ROUTE.md.orig-draft1`).

Revised 2026-09-20: `deviceId` is gone from the wire format. Advertisements, the `/ping`
response and `prepare` carry the fingerprint only; each side truncates it locally. A
transmitted id is an unauthenticated claim that every handler must remember to check — the
field's absence deletes that check class (§3, §4 Transport, §5).

## 0. Decision snapshot

| Topic | Decision |
|---|---|
| v1 scope | Device-to-device file transfer over LAN. Files only. |
| Platforms | Five eventual (Windows, macOS, Linux, Android, iOS/iPadOS). **Near-term: Windows + Linux.** Mobile is deferred until desktop is end-to-end stable, and is built only if §1.2 held. |
| Form | One C++/Qt codebase, native app per platform. Personal use, sideloaded to my own devices. Never distributed, never published to an app store. |
| UI | Qt Quick (QML). Widgets cannot run on iOS/Android. |
| Language / framework | C++23, **Qt 6.11.x** |
| Build | CMake, `qt_add_qml_module` embeds QML into the binary |
| HTTPS server | **`QTcpServer` + `QSslServer` + hand-written minimal HTTP/1.1 parser.** Not `QHttpServer`. |
| TLS | Bundled OpenSSL 3.x, forced `openssl` backend, **mutual TLS** |
| Discovery | System DNS-SD where available; `mjansson/mdns` and UDP broadcast as the portable fallback. Service type `_lanpipe._tcp`. |
| Transfer | HTTPS, JSON metadata + raw body stream |
| Security | Device keypair + SPKI fingerprint, nonce-based SAS pairing, trust list, approval prompt, block list |
| Licensing | Personal, non-distributed use, so LGPLv3 obligations are not triggered and no commercial Qt license is needed. See §2.1 for the boundary. |
| Out of scope v1 | Folders, text/clipboard, resume, headless server, LocalSend interop, mobile platforms, distribution of any kind |

## 1. Architecture

One codebase, three layers. The core layer compiles without GUI and is testable headless.

```
┌────────────────────────────────────┐
│ QML UI (Qt Quick)                  │  send, receive, devices, pairing, settings
├────────────────────────────────────┤
│ App controller (C++)               │  wires UI ↔ core, exposes QAbstractListModel
├────────────────────────────────────┤
│ Core (C++23, QtNetwork + OpenSSL)  │
│  ├ Identity    keypair, self-signed cert, SPKI fingerprint    │
│  ├ Discovery   DNS-SD backends + UDP broadcast, PeerDirectory │
│  ├ Trust       paired-peer store, accept policy, block list    │
│  ├ Transfer    send sessions, receive sessions, progress       │
│  ├ Files       FileSource / FileSink — no raw paths in core    │
│  ├ Http        minimal HTTP/1.1 server + client framing        │
│  └ Settings    QSettings (name, receive folder, policy)        │
├────────────────────────────────────┤
│ Platform shims (small, isolated)   │
│  Desktop: OpenSSL deployment, firewall hint, installers        │
│  Android (deferred): NsdManager, UIDT job, ACCESS_LOCAL_NETWORK, SAF, MediaStore │
│  iOS (deferred): NWListener/NWBrowser Bonjour, Info.plist, sideload flow │
└────────────────────────────────────┘
```

### 1.1 Layering rules

1. No UI code may call sockets.
2. No core code may import QML/Quick.
3. **No core code may touch a filesystem path.** All file I/O goes through `FileSource` /
   `FileSink` (§1.2.1).
4. Core exposes a **reachability state** ("can be discovered and served" / "cannot serve").
   Platform shims drive it — Android foreground service state, iOS background transition.
   Receive policy and UI must be able to express "currently unreachable".

### 1.2 Cross-platform hard constraints — must hold from the first line of code

Mobile platforms are deferred, but they are still the eventual target. Each item below is cheap
now and expensive later, because deferring it means reworking the core layer rather than adding
a platform shim.

1. **File I/O goes through an interface.** Core takes a `FileSource`
   (`open()` / `size()` / `displayName()`) and a `FileSink`, never a `QString path`. Desktop
   implements them over `QFile`. Mobile needs content URIs whose size may be null, and
   security-scoped URLs on iOS. If M3's transfer engine consumes paths directly, the engine is
   rewritten at mobile time.
2. **Mutual TLS from day one.** Adding client certificates later touches the crypto layer, the
   trust store and the receive policy at once. A desktop-only single-direction TLS phase is a
   trap.
3. **Receive-directory resolution goes through an interface.** The default location differs per
   platform (free path / app-private dir / SAF tree / Documents); it must not be hardcoded in
   `Settings`.
4. **The HTTPS port is configurable and travels in SRV and in the broadcast payload.** Fixed
   ports collide and are unavailable in some sandboxes.
5. **Key and certificate storage uses `QStandardPaths`,** never a concatenated absolute path.
   iOS container UUIDs change across reinstall and update.
6. **Filename sanitization is written to the strictest platform rules from the start**
   (Windows reserved names and full-path length, case-insensitive collision on Windows/macOS,
   NFD normalization on macOS). Windows alone already requires most of these rules; a Linux-only
   relaxed implementation has to be rewritten.
7. **OpenSSL is bundled and the OpenSSL backend is forced on every platform from the start**
   (§2.5). Using the system OpenSSL on desktop works and then breaks on Android packaging.
8. **Notifications are behind an abstraction.** The receive policy's "auto-accept, notification
   only" needs a notification implementation on all five platforms; build the interface plus the
   desktop implementation now.
9. **No Qt private headers, no patched Qt.** Non-distribution makes both legally available, but
   this codebase must build on all five platforms, and private APIs behave differently per TLS
   backend (Schannel and SecureTransport do not have the OpenSSL internals). Allowed in
   throwaway debug scripts; never on the cross-platform path.
10. **Protocol version and capability fields are part of the wire format from v1** (`ver` in TXT
    and `/ping`), so a future mobile build with different constraints can refuse early and
    clearly.

## 2. Stack

1. **Qt 6.11.x**, open source (LGPLv3).

   Why not 6.8 LTS: LTS patch releases are commercial-only. Open-source users get maintenance
   until the next minor (about 6 months), then patches delayed by 12 months. Evidence: the
   public 6.8 tree tops out at 6.8.4 (published 2026-07-09) while commercial is at 6.8.8. The
   next LTS is 6.12. Plan to move to each new minor roughly every 6 months, or cherry-pick the
   security diffs Qt publishes under `download.qt.io/official_releases/qt/<minor>/`.

   **Licensing boundary:** this project is personal, sideloaded to my own devices, and never
   distributed. LGPL and GPL obligations attach to distribution, so they are not triggered here,
   and GPLv3-only Qt modules (Qt HTTP Server, Qt GRPC, Qt MQTT, …) would be usable — none are
   used. If this project is ever given to someone else or released as a binary, the analysis
   changes: GPLv3-only modules become off-limits for a closed-source build, iOS's mandatory
   static linking triggers LGPLv3 §4(d)(0) relinkability plus Installation Information, Qt's own
   documentation names app stores as potentially incompatible, and Qt does not permit mixing
   open-source and commercial Qt code — that decision has to be made before the distribution,
   not retrofitted.

2. **C++23.** No Boost. Dependencies: Qt Network, Qt Quick, OpenSSL 3.x, and one mDNS library.
   Toolchain floors: GCC 13+, Clang 17+, MSVC 2022 17.8+, Xcode 15+, Android NDK r26+.

3. **UI: QML.** One touch-first UI serves phone, pad and desktop.

4. **HTTP server: `QTcpServer` + `QSslServer` with a hand-written minimal HTTP/1.1 parser.**

   Why not `QHttpServer`:
   - `QHttpServerRequest::body()` returns a fully buffered `QByteArray` in every version from
     6.8 through 6.13-dev. There is no incremental request-body API. A 10 GB `PUT` would be
     buffered whole in memory, which breaks the M3 acceptance criterion directly.
   - 6.8 has no body-size limit at all (the body is simply accumulated). 6.11 added
     `setMaximumBodySize` (default 32 MiB) — that rejects large uploads rather than streaming
     them. Upstream tracks streaming upload as an open feature request (QTBUG-133690).
   - 6.8 also has no supported way to delay a response for 30 s: `QHttpServerResponder` is a
     stack object of the protocol handler, and the documented async form (a route returning
     `QFuture<void>` with a moved responder) only exists from 6.11.
   - Qt HTTP Server is GPLv3-only for open-source users, so it would be off-limits the moment
     this project is distributed.
   - Qt's own module documentation says to use it only on local or trusted networks — which this
     is — so the point above is about the buffering behaviour, not trust.

   Evaluated and rejected (2026-09): **cpp-httplib** (local copy v0.48.0; latest 0.50.1). It
   does have what `QHttpServer` lacks — a streaming `ContentReader` whose callback returns
   `false` to abort, timeout and payload-limit knobs, and a documented mTLS constructor — but
   the decisive surface is the parsing that runs *before* any of our code, which route choices
   cannot gate:
   - 19 server-side CVEs (2020–2026), concentrated in exactly the framing code we would expose:
     header CRLF injection (two rated 9.9, one 10.0 via internal-header shadowing), chunked
     unbounded allocation, trailer merging, percent-decoding performed after validation.
     Disclosure practice is good — every advisory shipped with its fix (15/21 within ±3 days),
     and OSS-Fuzz is enrolled — but two fixes were themselves incomplete (CVE-2025-53629; the
     0.47.0 IP-host verification fix, completed only in 0.48.0).
   - Keep-alive cannot be turned off (`set_keep_alive_max_count(0)` asserts; the default is
     100), and the keep-alive body-drain path — the one a "refuse the body, close the
     connection" mitigation depends on — had correctness bugs fixed as recently as 2026-05/07
     (issue #2450, PR #2504).
   - Handlers run on a blocking thread pool: a Qt thread boundary (no QObject access from
     handlers), a new failure class, and no connection cap (the request queue is unbounded by
     default and there is no `set_max_connections`; blog claims of one are wrong).
   - `ContentReceiver` carries no offset/total, so progress is hand-counted anyway; hardening
     defaults are unsafe (`max_queued_requests = 0` means unlimited; `payload_max_length = 0`
     disables the cap).
   - Pinning ≥ 0.50.1 is mandatory (0.48.0 already lacks two security fixes) and creates a
     standing version-tracking obligation.

   Our profile — five endpoints, `Content-Length` framing only, one request per connection,
   both ends our own code — eliminates those bug classes by *not implementing the features*
   (§5.15). That trade is available only to the hand-written parser.

   Documented fallback: if the hand-written parser's defect rate or cost exceeds the M1
   estimate, the fallback is cpp-httplib **≥ 0.50.1** pinned behind a single wrapper, entered
   only after it passes an adversarial entry test: a chunked request refused without being
   decoded; duplicate `Content-Length` refused; an oversized header block bounded; a
   never-terminating chunked body does not pin a worker thread; a refused body followed by
   `Connection: close` leaves no contamination for a pipelined request. Re-evaluations update
   this record instead of redoing the research.

   Sender side is unaffected: `QNetworkAccessManager::put(request, QIODevice *)` streams from a
   file without buffering.

   The parser is ours; the allowed subset and its hardening are specified in §5.15.

5. **TLS: bundle OpenSSL 3.x and force the OpenSSL backend.**

   Call `QSslSocket::setActiveBackend("openssl")` before any SSL class is used (backends cannot
   be mixed), then assert `availableBackends()` contains it and fail with a readable message.

   Rationale: Qt does not link OpenSSL — it `dlopen()`s it at runtime (`-openssl-runtime` is the
   autodetect default; `-openssl-linked` is off by default), and every symbol goes through Qt's
   private `q_SSL_*` wrappers, so the application cannot rely on OpenSSL symbols being present.
   The implicit default backend is platform-dependent — OpenSSL if available, otherwise Schannel
   on Windows and SecureTransport on Apple, otherwise cert-only. Linux and Android have no
   alternative backend. Those backends differ in ways that matter here:
   - Schannel cannot implement `QueryPeer` (optional client certificate) at all;
   - SecureTransport reports only client-side ALPN in `supportedFeatures()` — no certificate
     verification capability — and it imports the local certificate and private key into the
     system keychain, which is a UX and security burden for an app whose identity *is* a
     self-signed certificate.
   One backend everywhere removes a class of divergence that is very hard to diagnose.

   Qt has no public API to generate a keypair or a self-signed certificate (`EVP_PKEY_keygen`,
   `X509_new` and `X509_sign` do not appear anywhere in the Qt sources; `QSslKey` only parses
   existing keys). Qt's own examples shell out to `openssl`. So OpenSSL 3.x is a real dependency
   on every platform, including Android, where the libraries must be packaged into the APK/AAB.

6. **mDNS: prefer the system resolver per platform.**

   - Apple: Network.framework — `NWBrowser` to browse, `NWListener` with `.service` to
     advertise. Neither needs the multicast entitlement (only *arbitrary* service types and
     browsing *all* types do).
   - Windows 10 1809+: the **Win32 DNS-SD API** (`windns.h`: `DnsServiceRegister`,
     `DnsServiceBrowse`, `DnsServiceResolve`), not the WinRT
     `Windows.Networking.ServiceDiscovery.Dnssd` namespace. Microsoft's own reference marks that
     namespace's browsing half — `DnssdServiceWatcher`, `DnssdServiceInstanceCollection` — as
     *unsupported and subject to change or removal*, leaving only registration usable. The Win32
     functions are supported for desktop apps, need no package identity, and pull in neither
     C++/WinRT nor `RoInitialize`.
   - Linux: Avahi, **implemented** — over its D-Bus interface via QtDBus rather than by
     linking `libavahi-client`. Fewer build and packaging dependencies, and the failure mode is
     identical: both need `avahi-daemon` running. If the daemon is absent the backend reports it
     and the sender/receiver fall back to UDP broadcast.
   - Android: `NsdManager`, which does both registration and discovery, via
     `registerServiceInfoCallback` (`resolveService` is deprecated since API 34).

   The system daemon handles probing, instance-name conflict resolution, interface changes,
   sleep/wake and power management — and on Android it removes the need to hold a
   `WifiManager.MulticastLock`.

   `mjansson/mdns` is a packet codec, not a responder. It gives socket setup, query send and
   reply parse; probing (RFC 6762 §8.1), announcing, conflict resolution, TTL refresh, goodbye
   packets, per-interface handling and backoff are all still to be written. Keep it as the
   portable fallback behind the same `Discovery` interface, with UDP broadcast below that.

   If it is used, the event-loop integration needs an explicit shape: a `QSocketNotifier` with a
   zero-timeout poll of `mdns_query_recv`, or a dedicated thread — its receive call blocks with a
   timeout and will stall the Qt event loop otherwise.

   Qt has no mDNS or Bonjour API of its own (`QDnsLookup` is unicast-only, one-shot, and its own
   documentation warns it is unsuitable for DNS-SD SRV records; QTBUG-30823 has been open since
   2013).

7. **Toolchain:** CMake ≥ 3.21, Ninja. Android via Qt's CMake toolchain; iOS via CMake → Xcode
   project. Both deferred.

## 3. Discovery

1. Advertise service type `_lanpipe._tcp.local` with the HTTPS port. **The port is not fixed** —
   bind an ephemeral port and publish it in SRV (and in the broadcast payload). A fixed port
   collides between two instances on one machine and is unavailable in some sandboxes. A
   fixed-port override in Settings covers the case where a user wants to open a firewall port by
   hand. (Windows Firewall rules are per-application, not per-port, so the override is rarely
   needed.)

2. TXT records: `fp`, `name`, `ver`.
   - `fp` — the SPKI fingerprint, as an advertisement hint only. **It is never a trust anchor.**
     `deviceId` is not transmitted: the receiving side truncates this value itself (§3, last note).
   - `name` — arbitrary UTF-8. A single TXT string is capped at 255 bytes: escape and truncate.
   - `ver` — protocol version, integer. A major mismatch is refused with an explicit message.

3. Browse → resolve → connect. Results go into `PeerDirectory`, deduped by `deviceId`, merged
   across sources (DNS-SD and broadcast) and interfaces.

   **A peer holds a set of addresses, not one `ip:port`.** A machine with Wi-Fi, Ethernet, a VPN
   and a docker bridge has several addresses under one `deviceId`, and connecting to the wrong
   one costs 30–75 s in TCP SYN retries. Store the set with a `lastSeen` timestamp, try addresses
   in order with a short per-address connect timeout (≈3 s), and only when all fail fall back to
   re-querying DNS-SD, then broadcast, then manual entry.

   A DNS-SD browse result is a *stable list*, not a periodic announcement: Avahi reports a service
   once when it appears and once when it disappears. So that backend re-reports every live entry on
   a refresh timer (`kPeerRefreshInterval`), which makes the directory's rule — "not heard for
   `kPeerExpiry` means gone" — mean the same thing for both backends.

4. Fallback: UDP broadcast on a fixed port (e.g. 53001) every 2 s with jitter, payload carrying
   the same fields as the TXT set plus the port. Bind with `SO_REUSEADDR` so two instances can
   coexist on one machine. That broadcast passes where multicast is filtered is a **hypothesis
   to verify on real hardware in M2**, not a design assumption.

5. Last resort: manual IP:port entry in the UI.

6. Failure diagnosis must distinguish three cases, because they have different fixes:
   - nothing discovered at all → multicast filtered, client/AP isolation on the router, or (on
     Android 17+) a missing local-network permission;
   - discovered but cannot connect → firewall (on Windows, a denied prompt is never shown
     again);
   - connects but `prepare` never returns → the receiver cannot serve (backgrounded, or not
     accepting).
   Show a per-case hint and provide an exportable log. A peer-to-peer app with no backend has no
   other support channel.

7. IPv6: decide and document the policy per backend. An IPv4-only path loses IPv6-only networks
   and networks where v4 is filtered. **Decided for the broadcast backend: IPv4 only** — broadcast
   has no IPv6 equivalent (its counterpart is multicast, which DNS-SD already covers). The
   broadcast payload therefore carries no address family information, and the receiving side takes
   the family from the datagram's source address.

8. The user-visible device name is the TXT `name`, not the mDNS instance name — system DNS-SD
   renames conflicting instances automatically.

`deviceId` = truncated SPKI fingerprint (§4). It is derived locally — from the handshake
certificate, or from an advertised fingerprint — and is never a field on the wire. There is
therefore no claimed value to compare against a certificate, and no way for a peer to name
itself. Two devices never collide, and reinstalling keeps identity as long as the key survives.

## 4. Identity and security

### Identity

1. First run: generate an EC keypair and a self-signed certificate with a long validity
   (10 years), using OpenSSL (§2.5). Private key in app-private storage located through
   `QStandardPaths`; file mode 0600 on desktop.
2. **Fingerprint = SHA-256 of the SubjectPublicKeyInfo (SPKI)**, not of the certificate.
   `deviceId` is a truncated encoding of the same value.

   This is what makes certificate rotation possible. With a certificate-hash fingerprint, any
   regeneration invalidates every existing pairing at once, and the user-facing explanation is
   "device identity changed".

### Transport

TLS 1.2+ with self-signed certificates and **mutual authentication**:

- The client verifies the server's fingerprint against the value from discovery, and after
  pairing against the trust store.
- The server requires a client certificate. `QSslConfiguration::peerVerifyMode()` defaults to
  `AutoVerifyPeer`, which on a server behaves as `QueryPeer` — it *requests* a certificate and
  accepts a client that sends none. Set `VerifyPeer` explicitly.
- **The sender identity is never claimed, only resolved.** `prepare` carries no `sender.id`; the
  server takes the identity from the client certificate, which the connection layer already
  resolved. A transmitted id would be unauthenticated JSON that every handler had to remember to
  compare against the certificate — a check that is missing from one handler fails silently.
  Without the field there is nothing to compare and nothing to forget.
- Fail closed. A missing peer certificate, or a public key that cannot be parsed, is a
  rejection — never a skipped check.
- **The identity is resolved once, in the connection layer**, right after the handshake and before
  a single request byte is parsed: a missing certificate or an unparseable public key ends the
  connection there, and every handler receives the already-resolved identity. Handlers do not
  parse certificates and do not re-check. A check copied into each handler is a check that will
  eventually be missing from one of them, and a missing check fails silently.
- Verification is manual fingerprint comparison. Do not rely on Qt's default CA verification for
  self-signed certificates.
- `QSslServer::setSslConfiguration()` must be called before `listen()`.

Qt 6.11 facts verified against the source (each one silently breaks mTLS if missed):

- **`VerifyPeer` alone does not require a client certificate.** `missingCertificateIsFatal()`
  defaults to `false`, and the OpenSSL backend only adds `SSL_VERIFY_FAIL_IF_NO_PEER_CERT` when
  that flag is set (`qsslcontext_openssl.cpp`). Without it a certificate-less client produces an
  ignorable `NoPeerCertificate` error instead of a failed handshake. Set both.
- **Partial `ignoreSslErrors(list)` continues only if *every* received error is in the list**
  (`QSslSocketPrivate::verifyErrorsHaveBeenIgnored`, `qsslsocket.cpp`). Pass exactly the
  tolerated subset; if anything else is in the list, the handshake fails — which is the
  behaviour we want, so no separate check is needed.
- **A socket whose SSL errors are not ignored is *paused*, not dropped** (`PauseOnSslErrors`).
  Forgetting to handle `sslErrors` therefore presents as a hang, not as an error. Every path
  that can produce errors must reach a decision.
- **On a `QNetworkAccessManager` client the peer certificate must be read from
  `QSslError::certificate()`.** At `sslErrors` time `QNetworkReply::sslConfiguration()` still
  holds the configuration that was set on the request; the socket's configuration is forwarded
  on a separate queued signal (`qhttpthreaddelegate.cpp` → `qnetworkreplyhttpimpl.cpp`). All of
  our certificate-bearing error types carry the certificate.
- **`QSslServer` hands the socket over on `pendingConnectionAvailable`, not `newConnection`.**
  `QTcpServer` emits `newConnection()` from its accept loop right after `incomingConnection()`
  returns — before the TLS handshake, when `nextPendingConnection()` is still empty. Listening
  to `newConnection` loses every request silently: the connection is accepted, the client waits,
  and nothing is ever read.
- **The OpenSSL layer aborts a certificate-less client with a fatal alert before any application
  byte**, which is what makes "reject, do not answer" observable from the far side as a failed
  connection rather than an HTTP error.

### Pairing (TOFU + SAS)

The code must be computed **independently at both ends** and compared by the users. A code sent
over the wire protects nothing: a man in the middle simply relays it.

1. The sender includes a client nonce (`cnonce`) in `POST /api/v1/ping`, along with its device
   name. POST rather than GET because the receiver's user must see *who* is asking before being
   asked to type anything, and neither the query string nor a request header can carry a UTF-8
   name (§5.15 admits visible ASCII only).
2. Both sides compute `SAS = H(fp_A ‖ fp_B ‖ cnonce)`, where each `fp` is the certificate
   fingerprint **that side observed in the TLS handshake** — the client reads
   `QSslSocket::peerCertificate()`, the server reads the client certificate (guaranteed present
   by mTLS). Never use the value from discovery.

   **Only one nonce, and it comes from the sender.** Each side must be able to compute the code
   *before* it needs anything from the other, because the receiver types its half before it
   answers: with a receiver-supplied nonce the sender could not compute anything until the
   response arrived, while the receiver would be waiting for the sender's half to be displayed —
   a three-way deadlock. Dropping it costs nothing: what makes the two sides differ is `fp_A`
   versus `fp_B`, not freshness, and the MITM controls the relayed `cnonce` either way, so the
   grinding cost below is unchanged.
3. **Twelve digits, split into two halves, each end displaying one and requiring the other.**
   The digits are the first 8 bytes of the hash read as a big-endian integer, modulo 10¹², zero
   padded. The sender displays the first six and requires the second six as input; the receiver
   displays the second six and requires the first six. Each end compares the typed value with
   **its own** computation and aborts on a mismatch:

   ```
   1. sender    computes its half before sending, displays it, sends the ping
   2. receiver  computes its half, displays it, asks its user for the sender's half
   3. receiver  compares, then answers — 200 means it verified too, 403 means it did not
   4. sender    asks its user for the receiver's half, compares, writes the trust store
   ```

   The sender learns the receiver's verdict from the response; the receiver learns nothing about
   the sender's, and does not need to — each side's trust entry rests on its own comparison.

   Why split rather than both ends displaying the same six digits. The MITM knows every input —
   it terminates both TLS sessions, so it sees both certificates and the whole ping — and it may
   substitute the relayed `cnonce`. It can therefore **grind**: search a substituted `cnonce`
   until the sender's code equals the receiver's, about 10⁶ hashes, offline, milliseconds. Both
   screens then show the same six digits and a diligent user is defeated. Splitting makes both
   halves have to match, which costs 10¹² hashes, and gives each end an independent machine
   check — neither has to trust the other's claim that it compared. It also removes the "type the
   digits off your own screen" shortcut, which would otherwise let a lazy user self-confirm. The
   residual 10⁻⁶ chance that the two halves are equal is the same magnitude as the code's own
   strength and is not handled separately.
4. Both ends write the peer to the trust list with the observed fingerprint and name — on their
   own comparison, not on the other end's word.
5. After pairing, the trust store is the authority — subsequent connections are verified by
   fingerprint pinning, not by recomputing the SAS.

**There is no SAS cache.** Both comparisons happen inside the one ping round trip, so nothing has
to be remembered for a later request. An earlier revision cached the code until `prepare`; that
existed only because the receiver's comparison had been deferred to the approval prompt, and it
brought with it a lifetime constant that silently expired mid-flow.

**How long a pairing may take.** Both ends wait for their user up to `kSasInputWindow` (2 min),
and the sender's HTTP timeout sits above that (`kSenderHttpTimeout`, 3 min). The receiver waits
*before* answering, so its window is the one that bounds the round trip.

Why not derive the SAS from the TLS transcript: Qt exposes no keying material, no transcript, no
`SSL*` handle and no `SSLKEYLOGFILE` support — `export_keying_material` and equivalents do not
appear in the sources, and the only related hook is an undocumented build-time debug macro that
requires rebuilding Qt. `QSslConfiguration::sessionTicket()` is the serialization of each side's
own `SSL_SESSION`, so the two ends hold different bytes and it cannot serve as a shared secret.
The nonce exchange above gives the same property — a MITM must terminate two separate TLS
sessions with its own certificate, so the two sides compute different codes — using only public
API. Channel binding is the one construction that would make each grinding attempt cost a real
handshake instead of a hash; revisit it if Qt ever exposes the material.

Residual risk: a MITM on the first connection if a user types the wrong digits **and** the other
end confirms anyway, or if both halves coincide. Document it; do not over-engineer v1.

### Receive policy

| Sender state | Default behavior |
|---|---|
| Paired | Auto-accept, notification only |
| Unknown, or seen but unpaired | Prompt every time |
| Blocked | Never prompted, rejected outright |
| Open mode | Off by default, exists in Settings |

1. A **block list** with a persistent store and a Block action in the UI. Otherwise any peer on
   the LAN can raise approval prompts indefinitely, and prompt fatigue is the shortest path to
   the user clicking accept without reading.
2. Rate limit prompts per `deviceId`.
3. Incoming files land in the receive folder with collision-safe names
   (`photo.jpg` → `photo (1).jpg`). Never overwrite silently. Collision detection follows the
   target platform's case-sensitivity and normalization rules (§5.11).
4. Enforce the size the user approved (§5.3).
5. Free-space check before accepting (§5.4).

## 5. Transfer protocol (v1)

Receiver hosts the HTTPS server. Sender connects. All bodies streamed, never buffered whole.

End-to-end sequence: `docs/sequence-diagram.puml` (regenerated to match this revision).

```
POST /api/v1/ping                                    (JSON)
     { cnonce, name }
     → 200 { "name", "ver", "fp", "reachable" }               receiver verified too
       (no deviceId: the sender derives it from the fingerprint it saw in this handshake)
     → 403                                                    receiver's user typed a mismatch
     → 409                                                    another pairing is already in progress
     → 504                                                    no user input within 2 min
     Note: the receiver answers only after its user has typed — step 3 in §4 pairing.

POST /api/v1/prepare                                    (JSON)
     { sender: { name }, files: [ { id, name, size, mime } ], totalSize }
     Note: no nonce here — the SAS was settled at /ping (§4) — and no sender id either:
     the identity is the client certificate (§4 Transport).
     → 200 { sessionId }                     accepted
     → 403 { reason }                        rejected by user or policy
     → 409 { reason, retryAfter }            another session is active
     → 507                                   insufficient free space
     → 504                                   no user response within 30 s

PUT  /api/v1/upload/{sessionId}/{fileId}                (raw body, Content-Length)
     → 200                                   receiver streams to its temp dir, renames on the last byte
     → 410                                   session gone (cancelled, aborted, expired)
     → 409                                   body exceeds the approved size, or session mismatch

POST /api/v1/complete/{sessionId}
     → 200 { files: [ { id, bytes } ] }      receiver shows "received N files"

POST /api/v1/abort/{sessionId}
     → 200. Receiver tears down the session, deletes its temp data.
     Note: if the receiver cancels, it closes the in-flight PUT connection directly (no 410 is sent); subsequent PUTs return 410.
```

### Rules

1. The sender reads in 256 KB chunks; a 10 GB file allocates no more than one chunk. The sender
   uses `QNetworkAccessManager::put(request, QIODevice *)`.

2. **Each file is renamed into place when its own `PUT` returns 200**, not at `complete`.
   Renaming only at `complete` makes the entire session a single point of failure: a crash after
   the last byte leaves nothing usable. `complete` becomes a summary and the protocol's only
   end-to-end check — its response carries per-file byte counts for the sender to compare.

3. **The approved size is the cap.** Per file: the `size` the user saw. Per session: the
   `totalSize` the user saw. A `Content-Length` that disagrees with the declaration is rejected.
   Without this, the approval screen is decorative: a peer could obtain approval for 1 MB and
   send 100 GB.

4. **Free space is checked at `prepare` time**, and the receiver returns 507 rather than
   discovering the problem at 99% of a 10 GB transfer.

5. **Both sides can cancel.** The sender closes the socket or calls `abort`; the receiver can
   also cancel. On cancel, the receiver closes the in-flight PUT connection directly (no 410
   is sent to the ongoing transfer). Subsequent `PUT`s for that session return 410. The receiver
   owns the receive folder and must be able to stop a transfer it auto-accepted.

6. **Idempotency.** A new `PUT` for a `fileId` that already has temp data truncates it rather
   than appending, or returns 409 — otherwise a retried request corrupts the file. `prepare`
   needs an idempotency key or a session TTL.

7. **Temp files live in a session directory, not beside the destination:**
   `<receive-dir>/.lanpipe-tmp/<sessionId>/<fileId>` plus a `.part.meta` recording source name,
   session, sender fingerprint and declared length. This solves three problems at once:
   filenames never participate in path construction (so path traversal cannot happen at write
   time), v2 resume has the binding information it needs, and orphan cleanup is decidable. Temp
   entries older than 24 h are removed on startup and by a periodic sweep.

8. **Timeouts in both directions:** TCP keepalive, an idle timeout keyed on "no progress for N
   seconds", and a per-address connect timeout (§3.3). A killed peer process, a Wi-Fi-to-cellular
   handoff, or a locked phone all leave half-open connections that otherwise hang indefinitely.

9. **Protocol constants:** the receiver's decision window is 30 s; the sender's HTTP timeout is
   set explicitly above it (45 s). Do not call `QNetworkRequest::setTransferTimeout()` with no
   argument — its default is exactly 30 000 ms and would race the receiver's decision.

10. **Progress:** both sides compute bytes/total, but they are not the same counter — the sender
    counts bytes handed to the socket (ahead by one socket buffer plus one chunk), the receiver
    counts bytes on disk. The sender must not display "done" until the 200 arrives.

11. **Filenames** travel as UTF-8 JSON. The receiver sanitizes **before any path is
    constructed**, using the strictest platform rules: strip separators, resolve `..`, reject
    reserved names (Windows `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`), reject
    trailing dots and spaces, reject bidirectional control characters (U+202E and friends can
    disguise an extension), cap the **full path** at the platform limit rather than just the
    name, and compare for collisions case-insensitively (Windows, macOS) and under NFD
    normalization (macOS). A rule table with test vectors belongs in M4's acceptance criteria.

12. Multiple files: one `prepare`, sequential `PUT`s, one `complete`. Parallel upload is a v2
    optimization.

13. **One active session at a time.** A second `prepare` receives 409 with `retryAfter`. The
    listener caps concurrent connections and the server caps total concurrent sessions.

14. The sender's file source is a `FileSource` (§1.2.1), never a raw path. The size may be
    unknown (some Android providers return null), so `prepare` needs a defined behavior for that
    case — refuse with a readable error, or mark the file as size-unknown in the approval UI and
    switch the progress display to indeterminate.

15. **The HTTP parser is ours — so its hardening is ours, and so is the right to shrink the
    surface.** The subset below is closed: anything not listed is refused with 400 and a closed
    connection, never merely ignored.

    Accept only:

    - **One request per connection.** Every response carries `Connection: close` and the
      connection closes after it. This deletes the keep-alive bug class whole — request
      smuggling on reused connections, body-drain framing bugs (CVE-2026-34441; the same class
      as cpp-httplib issues #2450 / #2504). Cost: one TLS handshake per request, milliseconds
      on a LAN next to a multi-GB transfer.
    - **`Content-Length` framing only**, a single header, digits only, parsed in unsigned
      arithmetic with explicit overflow rejection. Do not copy Qt's `toULongLong()` → `qint64`
      conversion in `QHttpServerParser::contentLength()` (QTBUG-150275): above `INT64_MAX` it
      wraps negative, bypasses the size gate, and leaves the declared body bytes on the wire to
      be reinterpreted as the next request — a request-smuggling primitive.
    - **`Expect: 100-continue`** answered with a bare `100 Continue` before the body is read.
      curl sends it automatically for bodies over ~1 MB; without this, every manual `curl`
      test stalls about a second.
    - **A bounded header block**: max field count, max line length, max total size — constants
      shared with the connection cap in §5.13.

    Refuse outright (400 + close, before any body byte is read):

    - any `Transfer-Encoding` — chunked is the single largest CVE class in every HTTP parser
      (unbounded allocation, CL+TE ambiguity, chunk-size underflow). The sender never needs
      it: `QNetworkAccessManager` frames by `Content-Length`.
    - duplicate `Content-Length`, or `Content-Length` together with `Transfer-Encoding`.
    - trailers, compressed request bodies, multipart bodies, Range requests, and any request
      header echoed into a response — never copy request bytes into response bytes; that is
      the entire CRLF response-splitting class.
    - any method, path, or HTTP version outside the fixed endpoint set above.

    While streaming, the body cap is the approved size (§5.3): a body exceeding it is cut off
    mid-stream, its temp data removed, and the connection closed.

## 6. UI screens (QML)

1. **Send** — peer list (auto-refreshing model, status dot per peer), pick file → pick peer →
   transfer cards with progress and cancel.
2. **Receive** — approval prompt (sender name, file count, total size, an input for the sender's
   half of the SAS code — see §4 pairing), recent
   received list, per-OS "open folder" action.
3. **Devices** — paired list, unpair, block, fingerprint shown, manual IP entry.
4. **Settings** — device name, receive folder, receive policy, open mode toggle, fixed-port
   override, diagnostics export.

Core exposes peers and transfers as `QAbstractListModel`s; screens are thin.

## 7. Platform notes

Desktop is the near-term scope. Mobile rows are recorded here so the verified constraints are not
lost when that work is picked up.

| Platform | Status | Discovery | Storage | Packaging | Hard constraints |
|---|---|---|---|---|---|
| Windows | **near-term** | DNS-SD 1809+, else broadcast | Free path (Downloads default) | Installer (NSIS/Inno Setup) | First listen triggers the Windows Firewall prompt — show a hint before it appears, scope to private networks. If the user denies it, the rule is created as blocked and is never prompted again; provide a "fix firewall" deep link. |
| Linux | **near-term** | Avahi, else broadcast | Free path | AppImage (Flatpak later) | Ship Avahi or fall back to broadcast; no dependency on a system daemon being present. |
| macOS | deferred | Network.framework | Free path | Local build | Needs a Mac to build. No notarization needed for local use. Local Network permission prompt (`NSLocalNetworkUsageDescription`). |
| Android | deferred | `NsdManager` | App dir default; SAF for custom dir | APK, sideload | **Android 17 (targetSdk 37) makes local network access a runtime permission (`ACCESS_LOCAL_NETWORK`) covering both directions — including the HTTPS listener itself; failures are silent timeouts.** `DiscoveryRequest.FLAG_SHOW_PICKER` + `registerServiceInfoCallback` avoids the permission entirely. Do **not** declare it on targetSdk ≤ 36. Foreground service: `dataTransfer` does not exist; `dataSync` has a 6h/24h budget and the platform reference says not to use it for targetSdk 34+; the documented path for a user-initiated transfer is a **UIDT job** (JobScheduler, `RUN_USER_INITIATED_JOBS`, `setUserInitiated(true)`), with `connectedDevice` as an alternative FGS type. The service must be started while the app is visible. Qt 6.8/6.11 has no foreground-service API (QTBUG-85154). `MulticastLock` is only required on Android 12 and below or Android 13 without T extensions 7. |
| iOS / iPadOS | deferred | Network.framework (`NWBrowser` + `NWListener`) | App Documents + Files app (`UIFileSharingEnabled`) | Xcode, sideload | Browse **and** register need no multicast entitlement — only arbitrary service types do. The Local Network permission also gates **outgoing** connections, including manual IP entry, and **cannot be re-prompted**: remediation is only a trip to Settings. Detect denial via `NWBrowser`'s `.waiting` + `kDNSServiceErr_PolicyDenied` (-65570) or `NWConnection.currentPath?.unsatisfiedReason == .localNetworkDenied`. While the permission is undetermined, a local-network operation attempted **in the background** is denied silently and not recorded. **Close the listening socket and stop the Bonjour registration when backgrounding** — otherwise the kernel accepts connections the app never services, and a peer discovers a receiver that cannot answer. Receiving requires the app to be in the foreground; no `UIBackgroundModes` value grants listening. `NSLocalNetworkUsageDescription` + `NSBonjourServices` via `MACOSX_BUNDLE_INFO_PLIST`. Sideloading needs a Mac and an Apple ID: free account = 7-day re-sign cycle, $99/yr = 1 year. |

Qt-specific gaps confirmed for the mobile path: no foreground-service API, no mDNS/Bonjour API,
and Qt does not emit the iOS local-network Info.plist keys.

## 8. Project layout

```
lanpipe/
├─ CMakeLists.txt
├─ core/                      # QtNetwork + OpenSSL, no GUI
│  ├─ identity.{h,cpp}        # keypair, cert, SPKI fingerprint, keystore
│  ├─ discovery/
│  │  ├─ discovery.h          # interface
│  │  ├─ avahidiscovery.{h,cpp}      # Linux: Avahi over D-Bus (system DNS-SD)
│  │  ├─ dnssddiscovery.{h,cpp}      # Windows: Dnssd; macOS: Network.framework (pending)
│  │  ├─ mdnsdiscovery.{h,cpp}       # mjansson fallback
│  │  ├─ broadcastdiscovery.{h,cpp}
│  │  ├─ peerdirectory.{h,cpp}       # peers hold address sets
│  │  └─ peerconnector.{h,cpp}       # try the address set in order, short per-address timeout
│  ├─ http/
│  │  ├─ httprequest.h        # our framing: parse + hardening limits
│  │  └─ httpserver.{h,cpp}   # QTcpServer + QSslServer
│  ├─ transfer/
│  │  ├─ protocol.h           # endpoint + message definitions, constants
│  │  ├─ sendsession.{h,cpp}
│  │  └─ receivesession.{h,cpp}
│  ├─ files/
│  │  ├─ filesource.h         # open / size / displayName
│  │  ├─ filesink.h
│  │  ├─ localsink.{h,cpp}    # desktop implementation
│  │  └─ atomicwrite.{h,cpp}  # write-then-rename, shared by identity and trust
│  ├─ trust/
│  │  ├─ truststore.{h,cpp}   # paired peers + block list
│  │  ├─ sanitizer.{h,cpp}    # filename rules
│  │  └─ policy.{h,cpp}       # accept decisions, rate limiting
│  ├─ notify.h                # notification abstraction
│  └─ settings.{h,cpp}
├─ app/
│  ├─ main.cpp
│  └─ qml/{Main,Send,Receive,Devices,PairingDialog,Settings}.qml
├─ cli/                       # headless harness: serve/send/pair, --yes / --pin for CI
├─ platform/                  # desktop now; android/ and ios/ when mobile starts
├─ tests/                     # QtTest: protocol, discovery loopback, trust, sanitizer vectors
└─ docs/
```

## 9. Milestones

Order rationale: the core is built and proven headless first — QtTest plus a CLI harness instead
of GUI churn; QML is a thin client added once the protocol is frozen. Mobile starts only after
desktop 1.0 is in daily use, and only if §1.2 held. Sizes: S ≤ 2 days, M ≤ 1 week, L ≥ 2 weeks
(solo, rough).

| # | Milestone | Status | Size | Acceptance |
|---|---|---|---|---|
| M0 | Skeleton: core layout, CMake (C++23), OpenSSL bundling, QtTest, headless CLI harness (`serve` / `send` / `pair`, with `--yes` and `--pin` for non-interactive CI), CI (Linux + Windows, plus a compile-and-`ctest` macOS job as a portability canary) | **DONE** | S | Core builds and `ctest` passes on all three; CLI runs headless |
| M1 | Identity + TLS + receive server: cert generation via OpenSSL, SPKI fingerprint, keystore, `QTcpServer` + `QSslServer` + our HTTP parser (§5.15 subset), mutual TLS, `/ping` with nonces | **DONE** | M | `curl --cert --key` reaches `/ping`; a client without a certificate is rejected; fingerprint prints to console. Parser negative tests: `Transfer-Encoding: chunked` → 400 + close with the body never decoded; duplicate `Content-Length` → 400; malformed or overflowing `Content-Length` → 400; header block beyond the caps → 400; a body exceeding the declared size is cut off mid-stream; a client that stalls after the headers is closed by the idle timeout |
| M2 | Discovery: `Discovery` interface, system DNS-SD backend, UDP broadcast fallback, `PeerDirectory` with address sets | **PARTIAL** | M | Two headless instances on **two real machines** discover each other; `dns-sd` / `avahi-browse` sees the service; with mDNS disabled, broadcast still finds peers; a wrong-first-address case falls back within the connect timeout. **The Windows DNS-SD path cannot be accepted in CI**: GitHub runners resolve nothing over mDNS, so `tst_windnssd` skips there (`SKIP_RETURN_CODE`, visible as `***Skipped`) and the round trip is accepted on a real Windows desktop. The Linux/Avahi path *is* exercised in CI. |
| M3 | Transfer engine: prepare/upload/complete/abort, session temp dir, per-file rename, cancel in both directions, approved-size enforcement, free-space check, progress, idle timeout | not started | M | The sender identity is taken from the client certificate alone — `prepare` carries no id to compare against (§4 Transport); 1 GB desktop→desktop transfers correctly; cancel from either side leaves no temp data; 10 GB stays flat in memory; disk-full returns 507; a retried `PUT` does not corrupt; a killed peer times out instead of hanging |
| M4 | Pairing + policy: nonce SAS, trust store, auto-accept rules, block list, rate limiting, collision naming, filename sanitizer | **PARTIAL** | M | Via CLI harness: unknown sender → both sides show matching codes → paired → silent accept; a peer whose fingerprint changed is rejected; every hostile-filename vector is rejected; two concurrent `prepare`s → 409 |
| M5 | QML frontend — Send / Receive / Devices / Pairing / Settings on the existing core models; no core changes | not started | M | Full desktop flow via UI: discover, pair, transfer with progress; core untouched |
| M6 | Desktop 1.0: settings, history, error paths, installers, firewall hint, diagnostics export. No notarization, no store signing — local use only | not started | S–M | Windows and Linux installable and transferring in daily use |
| — | Mobile (Windows/Linux were the near-term scope) | L each | Only after M6, and only if §1.2 held without rework |

Total cost is not knowable until M4 lands; that point recalibrates everything after it.

**Abandon criteria:** if M4 runs past its estimate, lock the scope to desktop permanently and
delete the mobile sections rather than carrying them as debt.

## 10. Risks

Every risk maps to at least one acceptance criterion above; a risk with no test is a placebo.

| Risk | Impact | Mitigation | Tested at |
|---|---|---|---|
| HTTP parser defects (our code now) | Corruption, smuggling, crash | Closed subset (§5.15): `Content-Length` framing only, one request per connection, no chunked/compression/header-echo; negative tests in M1 | M1, M3 |
| Sender identity unchecked | Paired-peer impersonation; the whole receive policy collapses | Mutual TLS + identity resolved from the certificate only, no claimed id on the wire + fail-closed | M1, M4 |
| Large-file memory blowup | OOM on phones | Fixed-size chunks; no buffering anywhere in the path | M3 (10 GB flat) |
| Half-open connections | Transfers hang forever with no error | Keepalive, idle timeout, per-address connect timeout | M3 |
| Wrong address chosen for a multi-homed peer | 30–75 s stalls, apparent failures | Address sets + short per-address timeout + ordered fallback | M2, M3 |
| Disk full on the receiver | User approves a transfer that cannot complete | Free-space check at `prepare`, 507 | M3 |
| Approved size not enforced | Peer sends far more than the user approved | Cap = approved size, `Content-Length` cross-check | M3, M4 |
| Hostile filenames | Path traversal, mojibake, silent overwrite | Pre-path sanitizer, strictest platform rules, test vectors | M4 |
| Non-ASCII / case / normalization collisions | Two files silently overwrite each other | Platform-aware collision comparison | M4 |
| Prompt fatigue | Users accept without reading | Block list, rate limiting | M4 |
| OpenSSL not bundled or wrong backend selected | Silent behavioural divergence per platform | Explicit dependency, forced backend, startup assertion | M0, M1 |
| macOS/Clang portability drift | Late, expensive rework | Compile-only macOS CI job from M0 | M0 |
| Windows Firewall denied | Receiver unreachable, confusing UX | Pre-prompt hint, deep link to fix, distinct diagnosis | M2, M6 |
| Router AP/client isolation | Discovery and transfer both fail | Detect + hint; manual IP entry; cannot be bypassed in software | M2 |
| Certificate expiry or key loss | Mass unpairing | SPKI fingerprint + long validity; identity survives rotation | M1 |
| Qt minor upgrade breaks the build | Schedule slip | Follow minors (~6 months), keep platform code thin and isolated, no private APIs | Continuous |
| Cross-platform constraint violated during desktop work | Mobile becomes a rewrite | §1.2 checklist reviewed at each milestone | Every milestone |

## 11. v2 hooks (designed for, not built)

1. Folder transfer — `prepare` already takes a file list; add relative paths and a `type` field.
2. Text/clipboard — one more endpoint, or a zero-length file with a `kind: text` marker.
3. Resume — `Content-Range` on `PUT`. The temp-file layout (`.lanpipe-tmp/<sessionId>/<fileId>`
   plus `.part.meta`) already carries the binding information resume needs.
4. LocalSend interop — its protocol is public; a second protocol handler plus its discovery.
5. Headless/daemon mode on desktop + tray — core already has no GUI dependency.
6. Mobile platforms — see §7 for the constraints already verified.
7. Power-aware discovery (mobile): announce-only mode, backoff, and `NsdManager` rather than an
   app-held multicast lock on Android.
