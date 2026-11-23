# CVE-2026-90436: Apache Axis 1.x SOAP fault class instantiation

## Root cause
When Axis 1.x deserializes a SOAP Fault, it reads the `exceptionName` the
message carries and instantiates that class reflectively. An attacker who
can post a SOAP envelope therefore controls which class on the classpath
the JVM loads and constructs. With a suitable class, that is code
execution. Envelope parsing happens before any per-service authentication.

## Preconditions
- Axis 1.x through 1.4 (EOL, no fixed release), reachable over HTTP.
- A class on the classpath whose construction has useful side effects.
  This is why Red Hat scores it lower.

## In the wild
- N-able N-central, together with the 4EverAble2Shell bugs, to drop
  miners.
- Confluence Data Center through its Axis SOAP/XML-RPC APIs (Rapid7, around
  2026-11-13).
- KEV since 2026-11-18. A public Python PoC exists.

## Lab results (scripts/poc/axis1-soapfault-rce/lab, run 2026-11-21)
Stock Axis 1.4 webapp on Tomcat 9 / JRE 8. The verifier found
`/axis/services/Version?wsdl` (generator comment `Apache Axis version: 1.4`),
the services list, `AxisServlet`, and a pre-auth `getVersion` SOAP call that
returned `Apache Axis version: 1.4`, and reported AFFECTED. The fault payload
is never sent.

## Fix
The product vendor's patch (Atlassian, N-able). Migrate custom services to
Axis2. Block Axis paths if they are unused.

## Sources
See `skills/axis1-soapfault-rce/SKILL.md`.
