# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2023-06-29

### Fixed

- Fixed ECC library uninitialized error during taproot signature verification.

## [1.0.2] - 2023-06-28

Initial release.

### Added

- Generate raw toSpend and toSign BIP-322 transactions via the BIP322 class.
- Sign a BIP-322 signature using a private key via the Signer class.
- Verify a simple BIP-322 signature via the Verifier class.
