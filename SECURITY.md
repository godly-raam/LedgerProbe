# Security policy

## Authorized use only

LedgerProbe is for authorized security testing of systems you own or have explicit permission to test. It sends real requests, can perform mutations when explicitly enabled, and must not be pointed at production or third-party systems without written authorization. The bundled `mock-bank-api` is an intentionally vulnerable local fixture; never expose it to a network.

## Reporting a vulnerability in LedgerProbe

Do not open a public issue for a vulnerability. Report it privately through the repository's GitHub Security Advisory page:

<https://github.com/godly-raam/LedgerProbe/security/advisories/new>

Include the affected version, a minimal reproduction, the impact, and whether the issue involves the engine, a reporter, an integration, or the lab fixture. Do not include real credentials, customer data, or target secrets. You should receive an acknowledgement within seven days. Please allow time for a fix before public disclosure.

## Supported versions

| Version | Security fixes |
| --- | --- |
| `1.1.x` | Supported |
| Older releases | Not supported; upgrade to the latest `1.x` release |

## Scope

The security policy covers the LedgerProbe engine, its CLI, reporters, integrations, GitHub Action, and Docker image. The intentionally vulnerable local fixture (`mock-bank-api`) is not a vulnerability report target; findings in that fixture are expected lab behavior.
