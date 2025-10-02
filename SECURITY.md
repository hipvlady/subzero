<!--
Copyright (c) Subzero Development Team.
Distributed under the terms of the Modified BSD License.
-->

# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

We take the security of Subzero seriously. If you believe you have found a security vulnerability, please report it to us privately.

### How to Report

1. **Email**: Send details to [security@subzero.dev](mailto:security@subzero.dev)
2. **Subject**: Include "SECURITY" in the subject line
3. **Details**: Provide as much information as possible (see below)

### What to Include

Please include the following information:

- **Type of vulnerability**: Authentication bypass, injection, etc.
- **Affected components**: Which parts of the system are affected
- **Steps to reproduce**: Detailed steps to reproduce the vulnerability
- **Impact**: What an attacker could do with this vulnerability
- **Suggested fix**: If you have ideas for a fix (optional)
- **Proof of concept**: Code or screenshots demonstrating the issue (if safe to share)

### What to Expect

- **Initial response**: Within 48 hours
- **Updates**: Every 5 business days until resolved
- **Resolution timeline**: Based on severity
  - Critical: 1-7 days
  - High: 7-14 days
  - Medium: 14-30 days
  - Low: 30-90 days

### Disclosure Policy

- **Coordinated disclosure**: We follow coordinated disclosure practices
- **Public disclosure**: After a fix is released and sufficient time for users to upgrade
- **Credit**: We will credit you in the security advisory (unless you prefer to remain anonymous)

## Security Features

Subzero implements multiple layers of security:

### Authentication Security

- **Secretless authentication**: Private Key JWT (RFC 7523)
- **Token validation**: JIT-compiled token verification
- **Multi-factor authentication**: Support for various MFA methods
- **Token revocation**: Immediate token invalidation
- **Session management**: Secure session handling

### Authorization Security

- **Fine-grained access control**: Document-level permissions
- **Principle of least privilege**: Minimal permissions by default
- **Permission caching**: Secure, time-limited permission caching
- **Audit trails**: Comprehensive logging of authorization decisions

### Transport Security

- **TLS 1.2+**: Required for all connections
- **Certificate pinning**: Support for certificate pinning
- **HSTS**: HTTP Strict Transport Security enabled
- **Secure cookies**: HttpOnly, Secure, SameSite flags

### Threat Detection

- **Signup fraud detection**: ML-based anomaly detection
- **Account takeover protection**: Behavioral analysis
- **MFA abuse detection**: Pattern recognition
- **Bot detection**: Automated threat identification
- **Rate limiting**: Distributed rate limiting

### Data Protection

- **Encryption at rest**: All sensitive data encrypted
- **Encryption in transit**: TLS for all communications
- **Token vault**: Secure credential storage for AI agents
- **Secret management**: No secrets in code or logs
- **PII protection**: GDPR and HIPAA compliance modes

### API Security

- **Input validation**: Comprehensive request validation
- **Output encoding**: Prevention of injection attacks
- **CORS**: Configurable CORS policies
- **Content Security Policy**: CSP headers
- **Rate limiting**: Per-user and per-endpoint limits

### AI Security

- **Prompt injection detection**: OWASP LLM Top 10 mitigations
- **Content filtering**: Malicious content detection
- **MCP protocol security**: Secure AI agent communication
- **Token vault**: Isolated credential storage for agents

## Security Best Practices

### For Users

1. **Keep updated**: Always use the latest version
2. **Secure configuration**: Review and secure all configuration options
3. **Environment variables**: Never commit credentials
4. **TLS certificates**: Use valid, up-to-date certificates
5. **Monitoring**: Enable security monitoring and alerts
6. **Audit logs**: Regularly review audit logs
7. **Access control**: Implement least privilege principle
8. **Backups**: Maintain secure, encrypted backups

### For Contributors

1. **No secrets in code**: Never commit credentials or API keys
2. **Security testing**: Include security tests for new features
3. **Input validation**: Always validate and sanitize inputs
4. **Dependency updates**: Keep dependencies up to date
5. **Code review**: All changes must be reviewed
6. **SAST scanning**: Run static analysis tools
7. **Secure defaults**: Default configurations should be secure

## Known Security Considerations

### Deployment Security

- **Network isolation**: Deploy in isolated network segments
- **Access control**: Restrict access to management interfaces
- **Monitoring**: Implement comprehensive monitoring
- **Incident response**: Have an incident response plan

### Redis Security

If using Redis for caching:

- Enable authentication (`requirepass`)
- Use TLS for Redis connections
- Restrict network access
- Regular backups

### Auth0 Configuration

- Use strong client secrets
- Enable MFA for Auth0 account
- Regular audit of Auth0 configuration
- Monitor Auth0 logs

## Security Scanning

We use multiple security scanning tools:

- **Dependabot**: Automated dependency updates
- **CodeQL**: Static analysis for vulnerabilities
- **Trivy**: Container image scanning
- **npm audit**: JavaScript dependency scanning
- **Safety**: Python dependency vulnerability checking

## Compliance

Subzero supports compliance with:

- **GDPR**: General Data Protection Regulation
- **HIPAA**: Health Insurance Portability and Accountability Act
- **SOC 2**: Service Organization Control 2
- **ISO 27001**: Information security management

Configuration options available for compliance modes.

## Security Advisories

Security advisories are published at:
- GitHub Security Advisories: https://github.com/subzero-dev/subzero/security/advisories
- Mailing list: security-announce@subzero.dev

Subscribe to receive security updates.

## Bug Bounty

We currently do not have a bug bounty program, but we deeply appreciate security researchers who report vulnerabilities responsibly. We will:

- Acknowledge your contribution
- Credit you in security advisories (if desired)
- Provide updates on the fix timeline

## Contact

- **Security issues**: security@subzero.dev
- **General questions**: dev@subzero.dev
- **GitHub**: https://github.com/subzero-dev/subzero

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

---

**Last updated**: 2025-09-30

---

**Last updated:** 2025-10-02
