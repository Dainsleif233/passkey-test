# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025

### Added
- Initial release
- WebAuthn/FIDO2 passkey login support
- Usernameless/discoverable credential login
- User passkey management page
- Admin configuration page
- Chinese and English language support
- Browser compatibility detection
- CSRF protection
- Rate limiting
- User deletion cleanup

### Security
- One-time challenge with 5-minute expiration
- SHA-256 hash for credential ID storage
- User handle verification
- Banned user rejection
- Private key hidden from serialization