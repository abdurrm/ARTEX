---
name: roller-xmlrpc-rce
description: "Invoke this skill when a task touches an Apache Roller blog (any 4.x-6.1.5 install, or an unknown version exposing /roller-services/xmlrpc): assesses the unauthenticated XML-RPC vendor-extension deserialization RCE (CVE-2026-129448, same bug as CVE-2026-82384, CVSS 9.8, exploited in the wild November 2026). Remote work is fingerprinting plus a benign extension probe; deserialization payloads are lab-only."
---

# roller-xmlrpc-rce: Apache Roller XML-RPC deserialization (CVE-2026-129448 / CVE-2026-82384)

Under an **authorized** engagement only. This skill classifies the target as
affected / not affected / hardening-relevant (benign extension probe; deserialization payloads are never shipped), using the
vendored PoCs and lab under `scripts/poc/roller-xmlrpc-rce/`. Run every PoC against the
lab first (`scripts/poc/roller-xmlrpc-rce/lab/setup.sh`), then once against the
authorized target, and compare the outputs.

## Running the bundled scripts

Paths such as `scripts/poc/roller-xmlrpc-rce/...` are relative to this skill's base directory
(`<base>/scripts/poc/roller-xmlrpc-rce/`). The skill directory is read-only for agent processes,
so never write into it:

- `poc/` verifiers only read and print; run them in place, for example
  `python3 <base>/scripts/poc/roller-xmlrpc-rce/poc/<script>`.
- Before running `lab/setup.sh` (it writes its config files next to itself), copy the
  lab into the task working directory: `cp -r <base>/scripts/poc/roller-xmlrpc-rce/lab ./roller-xmlrpc-rce-lab`
  and run `./roller-xmlrpc-rce-lab/setup.sh` from there.

## What the bug is

- Roller exposes the MetaWeblog/Blogger API through Apache XML-RPC at
  `/roller-services/xmlrpc`.
- The servlet is configured with `enabledForExtensions=true`, which accepts
  Apache XML-RPC vendor extension types (`ex:` namespace). One of these is
  `ex:serializable`, which carries a Base64 Java serialized object.
- The request is parsed and deserialized **before** authentication is
  checked (CWE-502). Any gadget chain on Roller's classpath therefore gives
  unauthenticated RCE.
- Disabling the XML-RPC feature in the Roller admin UI does **not** help:
  the servlet mapping still parses requests.
- CVE-2026-82384 (patched September 2026) listed only 6.1.5. The ASF later
  confirmed CVE-2026-129448 is the same bug, covers older releases, and is
  exploited in the wild (advisory dated 2026-11-17/18).

## Affected / not affected

- Affected: Roller 4.0.0 through 6.1.4. Sources disagree on 6.1.5, so treat
  it as affected.
- Fixed: 6.1.6 (released 2026-09-24, disables extensions). Several sources
  recommend 6.1.7.
- Not affected: installs where `enabledForExtensions` is `false` in
  `WEB-INF/web.xml`, or where the `/roller-services/xmlrpc` mapping has been
  removed.

## Hard gates

1. **Authorization**: the target is in scope.
2. **No deserialization payloads on live targets**: `ex:serializable` with
   a gadget chain is RCE. It is lab-only unless the engagement explicitly
   authorizes one-shot exploitation. If it does, use a marker command only
   (for example `id > /tmp/<marker>` read back by the operator), then stop.
3. **Lab first**: reproduce against a Roller 6.1.4 container before drawing
   conclusions from probe responses.
4. **Compromise check**: the bug is exploited in the wild. With host
   access, hunt before advising.

## Detection workflow

1. **Exposure**: send `system.listMethods` (benign) and check whether the
   endpoint answers.
   ```bash
   curl -sk https://{host}/roller-services/xmlrpc -H 'Content-Type: text/xml' \
     -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>'
   ```
   An XML-RPC `methodResponse` or `fault` means the servlet is reachable. A
   404 means the mapping is gone.
2. **Version**: check the page footer ("Powered by Apache Roller x.y.z"),
   the `generator` meta tag, and `/roller-ui/` assets. With host access,
   read `roller.war`'s `META-INF/MANIFEST.MF`.
3. **Extension probe (benign, lab-calibrated)**: run the verifier.
   ```bash
   python3 scripts/poc/roller-xmlrpc-rce/poc/verify_extension_probe.py --target https://{host}/roller
   ```
   It interprets three observed behaviours (6.1.4 versus 6.1.7 in the lab):
   - **affected**: the fault response declares
     `xmlns:ex="http://ws.apache.org/xmlrpc/namespaces/extensions"`, and an
     `<ex:nil/>` parameter is parsed and reaches the auth check
     (`Invalid Username and/or Password`). That is the same parse path
     `ex:serializable` uses.
   - **patched 6.1.7**: HTTP 404 with `XML-RPC service is disabled`.
   - **extensions off**: the nil value fails at parse time.
   No serialized object is sent.
4. Classify:
   - **affected**: the endpoint is reachable and the version or probe says
     extensions are enabled;
   - **not affected**: the endpoint is gone, or the version is at least 6.1.6
     and the probe agrees;
   - **hardening-relevant**: anything ambiguous.

## Hunting (host access)

- Access logs: POSTs to `/roller-services/xmlrpc` carrying `ex:serializable`
  or large Base64 bodies.
- Child processes of the Tomcat/Java process (`sh`, `bash`, `curl`, `wget`).
- New JSP or WAR files in the webapps directory.

## Mitigation to cite

- Upgrade to 6.1.6 or later (6.1.7 recommended).
- If you cannot upgrade: set `enabledForExtensions` to `false` in
  `WEB-INF/web.xml`, or remove the `/roller-services/xmlrpc` servlet
  mapping, then restart.
- Block `/roller-services/xmlrpc` at the reverse proxy if nothing uses
  blogging clients.

## Reporting

- Title: Unauthenticated RCE via Apache Roller XML-RPC deserialization
  (CVE-2026-129448).
- Include: the version evidence, the endpoint response, the probe result
  from the lab-calibrated comparison, and any hunting hits.

## Vendored artifacts

Under `scripts/poc/roller-xmlrpc-rce/`:

- `poc/verify_extension_probe.py` - `system.listMethods` + `<ex:nil/>` probe; proves extension values are parsed before auth without sending a serialized object
- `lab/setup.sh` - Roller 6.1.4 (:18081) and 6.1.7 (:18082) on Tomcat 9 + Derby, loopback only (verified 2026-11-21: 6.1.4 -> VULNERABLE, 6.1.7 -> NOT AFFECTED)
- `docs/ANALYSIS.md` - root cause and the lab calibration table

## References

- https://thehackernews.com/2026/11/critical-apache-roller-rce-flaw-under.html
- https://phoenix.security/apache-roller-xml-rpc-deserialization-cve-2026-129448-rce/
- https://securityonline.info/apache-roller-vulnerability-cve-2026-129448/
- https://www.rescana.com/post/apache-roller-cve-2026-129448-xml-rpc-deserialization-rce-patch-now
