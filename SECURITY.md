# Security Policy

## Reporting a Vulnerability

Currently, [GitHub security advisories](https://help.github.com/en/articles/managing-security-vulnerabilities-in-your-project) is not activated on [eclipse](https://www.eclipse.org/) projects.

To report a vulnerability, your need to open a [bugzilla ticket](https://bugs.eclipse.org/bugs/enter_bug.cgi?product=Community&component=Vulnerability+Reports&keywords=security&groups=Security_Advisories).

For more details, please look at https://www.eclipse.org/security/.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.5.0-SNAPSHOT (master) | :heavy_check_mark: |
| 3.4.0   | :heavy_check_mark: |
| 3.3.1, 3.2.0, 3.1.0, 3.0.0 | :question: |
| 2.7.1   | :question: |
| 2.6.6, 2.5.0, 2.4.1, <br/> 2.3.1, 2.2.3, 2.1.0, <br/> 2.0.0 | :question: |
| before 2.0.0   | :x: |

:heavy_check_mark: development version / current release - all bugfixes will be applied

:question: the previous (bugfix-)releases - update to the current release is recommended. On exceptions, specific bugfixes may be applied on request. (Create a vulnerability report with the requested vulnerability fix and the (bugfix-)version.)

:x: old releases, milestone releases - usually no bugfixes are applied there.

## Known Vulnerabilities Of Dependencies

| Californium Version | Dependency | Affected Version | Usage | Vulnerability
| ------------------- | ---------- | ---------------- | ----- | -------------
| < 3.3 <br/> < 2.7.2 | com.upokecenter.cbor | 4.0 - 4.5.0 | cf-oscore <br/> demo-apps | [GHSA-fj2w-wfgv-mwq6](https://github.com/peteroupc/CBOR-Java/security/advisories/GHSA-fj2w-wfgv-mwq6)
| < 3.2 <br/> < 2.7.1 | ch.qos.logback.logback-classic | < 1.2.9 | demo-apps | [CVE-2021-42550](https://cve.report/CVE-2021-42550)
