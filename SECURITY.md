# Security Policy

## Supported Versions

`secrets4` is pre-1.0. Security fixes target the current `main` branch.

## Reporting A Vulnerability

Please report suspected vulnerabilities privately to the repository owner
instead of opening a public issue with exploit details. Include:

- affected commit or release
- operating system
- steps to reproduce
- expected and observed behavior
- whether any secret material may have been exposed

The project will acknowledge confirmed reports, fix on `main`, and document
user action needed for incident response.

## Current Security Boundary

`secrets4` is a local single-user tool. It protects an offline copy of
`cache.enc`, `cache.key`, and `install.id` from decryption without the master
password. It does not defend against code already running as the same user,
or against a live automation environment that intentionally supplies
`SECRETS4_PASSWORD`.
