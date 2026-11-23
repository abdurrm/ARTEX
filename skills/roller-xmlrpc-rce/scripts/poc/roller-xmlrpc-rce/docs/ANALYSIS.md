# CVE-2026-129448 / CVE-2026-82384: Apache Roller XML-RPC deserialization

## Root cause
Roller maps Apache XML-RPC's `XmlRpcServlet` at `/roller-services/xmlrpc` with
`enabledForExtensions=true` in `WEB-INF/web.xml`. You can confirm this in the
6.1.4 `roller.war`. With extensions enabled, the XML-RPC parser accepts
vendor types in the `http://ws.apache.org/xmlrpc/namespaces/extensions`
namespace, including `ex:serializable`, which is a Base64 Java serialized
object that `ObjectInputStream` reads. Parsing happens **before** Roller's
handler checks credentials, so deserialization is pre-auth (CWE-502). A gadget
chain on Roller's classpath turns that into RCE.

## Preconditions
- Roller 4.0.0 through 6.1.4 (6.1.5 per CVE-2026-82384). The servlet mapping
  must be present.
- Turning off "enable XML-RPC" in the admin UI does not stop the parser on
  affected versions.

## Fix
6.1.6 (2026-09-24) disables extensions. 6.1.7 also answers
`XML-RPC service is disabled` by default.

## Lab calibration (scripts/poc/roller-xmlrpc-rce/lab, run 2026-11-21)

| Probe | 6.1.4 | 6.1.7 |
|---|---|---|
| `system.listMethods` | XML-RPC fault whose `methodResponse` declares `xmlns:ex=".../extensions"` | HTTP 404, `XML-RPC service is disabled` |
| `<ex:nil/>` as the first `blogger.getUsersBlogs` parameter | parsed, then `Invalid Username and/or Password` (auth check reached) | same 404 |

The `ex:nil` result shows that extension values are parsed before the auth
decision, which is the same path `ex:serializable` takes. No serialized
object is ever sent.

## Evidence in the wild
ASF confirmed exploitation (advisory dated 2026-11-17/18).

## Sources
See `skills/roller-xmlrpc-rce/SKILL.md`.
