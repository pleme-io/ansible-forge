# Security Policy

## Reporting a vulnerability

**Do not open public issues for security bugs.**

Use GitHub's [Private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository.

If unavailable, email `security@pleme.io` <!-- TODO: replace with real address before launch --> with a description, affected versions, and reproduction steps.

## Response targets

| Step | Target |
|---|---|
| Acknowledgement | 5 business days |
| Triage + severity | 10 business days |
| Coordinated disclosure | 90 days from acknowledgement |

## Scope

In scope:

- The Rust crate at `src/` — generator correctness, output safety
- Generated Python module shape (escape correctness, no command injection, etc.)
- The `module_utils/akeyless_client.py` helper bundled in `src/client_helper.rs`

Out of scope (report upstream):

- The `iac-forge` IR or resolver → [`pleme-io/iac-forge`](https://github.com/pleme-io/iac-forge)
- The Akeyless API itself → [Akeyless support](https://www.akeyless.io/contact-us/)
- The published Ansible collection → [`pleme-io/ansible-akeyless-gen`](https://github.com/pleme-io/ansible-akeyless-gen)

## Supported versions

| Version | Status |
|---|---|
| `0.2.x` | Active |
| `< 0.2` | Unsupported |
