# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-07

### Added
- `pwtool check`: strength analysis with entropy estimation, pattern detection
  (dictionary/leetspeak, keyboard walks, sequences, repeats, dates), bundled
  10k common-password list, 0-4 score, crack-time estimates and suggestions.
- `pwtool breach`: Have I Been Pwned Pwned Passwords lookup using k-anonymity
  (5-char SHA-1 prefix, `Add-Padding` header, retries with backoff).
- `pwtool generate`: CSPRNG passwords (`secrets`) and EFF-wordlist passphrases.
- Rich terminal UI, `--json` output, `--stdin` input, `--min-score` exit codes.
- pytest suite (143 tests, 99% coverage), ruff and mypy (strict) configuration.
