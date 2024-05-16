# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-05-16

### Added

- Added regtest support for signing and verifying BIP-137 and BIP-322 signatures.
- Added `useStrictVerification` argument in `Verifier.verifySignature`. See README for its usage.

### Changed

- Removed `network` argument in `Signer.sign`; the network is now automatically inferred from the given address.
- Moved `Address.compressPublicKey` and `Address.uncompressPublicKey` to `Key.compressPublicKey` and `Key.uncompressPublicKey` respectively.
- Updated dependencies.

## [1.1.1] - 2024-04-05

### Fixed

- Fixed issue #7 where BIP-137 signatures that were signed using flags for P2SH/P2WPKH would fail verification incorrectly.

## [1.1.0] - 2023-08-20

### Added

- Added support for BIP-137 legacy signature verification against P2SH-P2WPKH, P2WPKH, and single-key-spend P2TR addresses.

## [1.0.3] - 2023-06-29

### Fixed

- Fixed ECC library uninitialized error during taproot signature verification.

## [1.0.2] - 2023-06-28

Initial release.

### Added

- Generate raw toSpend and toSign BIP-322 transactions via the BIP322 class.
- Sign a BIP-322 signature using a private key via the Signer class.
- Verify a simple BIP-322 signature via the Verifier class.
