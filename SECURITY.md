# Security Policy

## Reporting a Vulnerability

Californium supports the use of [GitHub security advisories](https://help.github.com/en/articles/managing-security-vulnerabilities-in-your-project) as pilot for [eclipse](https://www.eclipse.org/) projects.

To report a vulnerability, [go directly to the form](https://github.com/eclipse-californium/californium/security/advisories/new). Alternatively, switch to the [Security tab](https://github.com/eclipse-californium/californium/security), then click "Report a vulnerability" and another "Report a vulnerability" button again.

You may also report a vulnerability opening a [bugzilla ticket](https://bugs.eclipse.org/bugs/enter_bug.cgi?product=Community&component=Vulnerability+Reports&keywords=security&groups=Security_Advisories).

For more details, please look at [https://www.eclipse.org/security](https://www.eclipse.org/security).

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.11.0-SNAPSHOT (main) | :heavy_check_mark: |
| 3.10.0 | :heavy_check_mark: |
| 3.9.1, 3.9.0, 3.8.0,<br/> 3.7.0, 3.6.0, 3.5.0,<br/> 3.4.0, 3.3.1, 3.2.0,<br/> 3.1.0, 3.0.0 | :question: |
| 2.8.0   | :question: |
| 2.7.4, 2.6.6, 2.5.0,<br/> 2.4.1, 2.3.1, 2.2.3,<br/> 2.1.0, 2.0.0 | :question: |
| before 2.0.0   | :x: |

:heavy_check_mark: development version / current release - all bugfixes will be applied

:question: the previous (bugfix-)releases - update to the current release is recommended. On exceptions, specific bugfixes may be applied on request. (Create a vulnerability report with the requested vulnerability fix and the (bugfix-)version.)

:x: old releases, milestone releases - usually no bugfixes are applied there.

## Known Vulnerabilities

| Californium Version | Vulnerability
| ------------------- | ----------
| < 3.7 <br/> < 2.7.4 | Failing DTLS handshake [CVE-2022-39368](https://cve.report/CVE-2022-39368)
| < 3.6 <br/> < 2.7.3 | DTLS resumption handshake [CVE-2022-2576](https://cve.report/CVE-2022-2576)
| < 3.0-M3 <br/> < 2.6.5 | DTLS certificates verification bypass [CVE-2021-34433](https://cve.report/CVE-2021-34433)
| < 2.6.0 | DTLS certificates verification fails sticky [CVE-2020-27222](https://cve.report/CVE-2020-27222)

See also [NIST database of known Californium vulnerabilities](https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=Californium&search_type=all)

## Known Vulnerabilities Of Dependencies

| Californium Version | Dependency | Affected Version | Usage | Vulnerability
| ------------------- | ---------- | ---------------- | ----- | -------------
| < 3.6 <br/> < 2.7.3 | com.google.code.gson |  < 2.8.9 | demo-apps | [CVE 2022-25647](https://cve.report/CVE-2022-25647)
| < 3.3 <br/> < 2.7.2 | com.upokecenter.cbor | 4.0 - 4.5.0 | cf-oscore <br/> demo-apps | [GHSA-fj2w-wfgv-mwq6](https://github.com/peteroupc/CBOR-Java/security/advisories/GHSA-fj2w-wfgv-mwq6)
| < 3.2 <br/> < 2.7.1 | ch.qos.logback.logback-classic | < 1.2.9 | demo-apps | [CVE-2021-42550](https://cve.report/CVE-2021-42550)

## Known Vulnerabilities Of Runtime Dependencies

| Californium Version | Dependency | Affected Version | Usage | Vulnerability
| ------------------- | ---------- | ---------------- | ----- | -------------
| < 3.5 | JDK / JCE | <= 15.0.2? <br/> <= 16.0.2? <br/> < 17.0.3 <br/> < 18.0.1 | execution environment | ECDSA [CVE-2022-21449](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21449)
| < 3.10 | logback | < 1.2.13 | logging implementation | Remote appender [CVE-2023-6378](https://nvd.nist.gov/vuln/detail/CVE-2023-6378)<br/>[CVE-2023-6481](https://nvd.nist.gov/vuln/detail/CVE-2023-6481)
