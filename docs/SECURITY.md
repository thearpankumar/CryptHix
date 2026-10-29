# Security policy

CryptHix is pre-release: no version is supported for production use yet, and the on-disk format may still change ([format spec](format-spec.md)). Reports are still welcome and are handled the same way they will be after the first release.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. If you cannot use it, email **arpankumar1119@gmail.com**. Do not open a public issue, pull request or discussion for a suspected vulnerability.

Please include:

- what an attacker can do, and which attacker from the [threat model](threat-model.md) it assumes;
- the commit or version, and the steps or a test case that shows it;
- any fix or mitigation you have in mind.

You can expect an acknowledgement within 7 days. Fixes are developed in a private advisory and published with credit to the reporter, unless you ask not to be named.

## Scope

In scope: anything that breaks a property the [threat model](threat-model.md) claims for an implemented phase, including the format and crypto ([format spec](format-spec.md)), the build and CI pipeline, and the vendored test vectors.

Out of scope: attacks the threat model lists as out of scope, and weaknesses in features that are still only planned.
