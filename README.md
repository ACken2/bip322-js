# BIP322-JS

![Unit Test Status](https://github.com/ACken2/bip322-js/actions/workflows/unit_test.yml/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/ACken2/bip322-js/badge.svg?branch=main)](https://coveralls.io/github/ACken2/bip322-js?branch=main)

A Javascript library that provides utility functions related to the BIP-322 signature scheme.

## Documentation

Available at https://acken2.github.io/bip322-js/

## Supported Features

The following features are supported on mainnet, testnet, and regtest 
for P2PKH, P2SH-P2WPKH, P2WPKH, and single-key-spend P2TR addresses:

1. Generate raw toSpend and toSign BIP-322 transactions.
2. Sign a BIP-322 signature using a private key.
3. Verify a legacy BIP-137 signature loosely (see below).
4. Verify a simple BIP-322 signature.

## Usage

Use the **Signer** class to sign a BIP-322 signature:
```js
Signer.sign(privateKey, address, message)
```

Use the **Verifier** class to verify a BIP-322 signature (which also validates a BIP-137 signature):
```js
Verifier.verifySignature(address, message, signature)
```

## Loose BIP-137 Verification

A BIP-322 signature is backward compatible with the legacy signature scheme (i.e., BIP-137 signature). 
As a result, this library also recognizes valid BIP-137 signatures.

In a BIP-137 signature, a header flag indicates the type of Bitcoin address for which the signature is signed:
- 27-30: P2PKH uncompressed
- 31-34: P2PKH compressed
- 35-38: Segwit P2SH
- 39-42: Segwit Bech32

However, some wallets' implementations of the BIP-137 signature did not strictly follow this header flag specification, 
and some may have signed signatures with the wrong header (e.g., using header 27 for a native segwit address).

It is trivial, however, to convert a BIP-137 signature with an incorrect header flag to one with the correct header 
flag since the "address type" component in the header flag is not part of the actual signature.

As such, some BIP-137 signature verifiers online, such as [this one](https://www.verifybitcoinmessage.com/), 
actively help to swap out any erroneous header flags.

This library defines this behavior as **"Loose BIP-137 Verification"**.

This behavior assumes that a signature proving ownership of the private key associated with public key $X$ 
is valid for all addresses $y_1$, $y_2$, ..., $y_n$ derivable from the same public key $X$.

This behavior is enabled by default in this library, but can be disabled by passing the 
optional useStrictVerification flag in Verifier.verifySignature:

```js
Verifier.verifySignature(signerAddress, message, signatureBase64, true)
```

Consequently, this also allows BIP-137 signatures to be used for taproot addresses, which is technically out-of-spec 
according to both BIP-137 and BIP-322 specifications, as implemented by some wallet implementations. 
Please refer to [issue #1](https://github.com/ACken2/bip322-js/issues/1) for relevant discussions.

Note that this behavior does not exist in actual BIP-322 signature due to how BIP-322 signature is constructed.

## Example

```js
// Import modules that are useful to you
const { BIP322, Signer, Verifier } = require('bip322-js');

// Signing a BIP-322 signature with a private key
const privateKey = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
const address = 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l'; // P2WPKH address
const addressTestnet = 'tb1q9vza2e8x573nczrlzms0wvx3gsqjx7vaxwd45v'; // Equivalent testnet address
const addressRegtest = 'bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vay85cr9'; // Equivalent regtest address
const taprootAddress = 'bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3'; // P2TR address
const nestedSegwitAddress = '37qyp7jQAzqb2rCBpMvVtLDuuzKAUCVnJb'; // P2SH-P2WPKH address
const message = 'Hello World';
const signature = Signer.sign(privateKey, address, message);
const signatureTestnet = Signer.sign(privateKey, addressTestnet, message); // Wworks with testnet address
const signatureRegtest = Signer.sign(privateKey, addressRegtest, message); // And regtest address
const signatureP2TR = Signer.sign(privateKey, taprootAddress, message); // Also works with P2TR address
const signatureP2SH = Signer.sign(privateKey, nestedSegwitAddress, message); // And P2SH-P2WPKH address
console.log({ signature, signatureTestnet, signatureRegtest, signatureP2TR, signatureP2SH });

// Verifying a simple BIP-322 signature
const validity = Verifier.verifySignature(address, message, signature);
const validityTestnet = Verifier.verifySignature(addressTestnet, message, signatureTestnet); // Works with testnet address
const validityRegtest = Verifier.verifySignature(addressRegtest, message, signatureRegtest); // And regtest address
const validityP2TR = Verifier.verifySignature(taprootAddress, message, signatureP2TR); // Also works with P2TR address
const validityP2SH = Verifier.verifySignature(nestedSegwitAddress, message, signatureP2SH); // And P2SH-P2WPKH address
console.log({ validity, validityTestnet, validityRegtest, validityP2TR, validityP2SH }); // True

// You can also get the raw unsigned BIP-322 toSpend and toSign transaction directly
const scriptPubKey = Buffer.from('00142b05d564e6a7a33c087f16e0f730d1440123799d', 'hex');
const toSpend = BIP322.buildToSpendTx(message, scriptPubKey); // bitcoin.Transaction
const toSpendTxId = toSpend.getId();
const toSign = BIP322.buildToSignTx(toSpendTxId, scriptPubKey); // bitcoin.Psbt
// Do whatever you want to do with the PSBT
```

More working examples can be found within the unit test for BIP322, Signer, and Verifier.

## Migration Guide from v1.X

There are only two non-backward-compatible changes in the API:

1. If you previously used `Address.compressPublicKey` or `Address.uncompressPublicKey`, 
replace them with `Key.compressPublicKey` and `Key.uncompressPublicKey` respectively.

2. In v1.X, there was an option to pass the `network` parameter into `Signer.sign`: `Signer.sign(privateKey, address, message, network)`. 
This option has been removed, as the network is now automatically inferred from the given address.