# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial project structure, documentation, tooling, and CI configuration.
- Phase 0 foundation: root-package configuration with secure defaults,
  composed Store, Mailer, PasswordHasher, RateLimiter and Clock contracts,
  default User, Account, Session and Token model, sentinel errors, and a
  router-agnostic HTTP surface with placeholder endpoints.
- Domain glossary and decision records for the Go version floor and the
  root-package API boundary.
- Phase 1 email and password authentication: programmatic and HTTP sign-up,
  sign-in and sign-out, Argon2id verifiers with OWASP parameters, a bcrypt
  adapter, transparent rehash, anti-enumeration timing, rate limiting,
  Sessions with hashed tokens, redacted hooks and structured events.
  `golang.org/x/crypto` is the only third-party dependency, used for Argon2id
  and bcrypt.
