# BIP322-JS

![Unit Test Status](https://github.com/ACken2/bip322-js/actions/workflows/unit_test.yml/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/ACken2/bip322-js/badge.svg?branch=main)](https://coveralls.io/github/ACken2/bip322-js?branch=main)

A Javascript library that provides utility functions related to the BIP-322 signature scheme.

## Limitations

Only P2PKH, P2SH-P2WPKH, P2WPKH, and single-key-spend P2TR are supported in this library.

## Documentation

Available at https://acken2.github.io/bip322-js/

## Supported Features

1. Generate raw toSpend and toSign BIP-322 transactions
2. Sign a BIP-322 signature using a private key
3. Verify a simple BIP-322 signature

## Example

```js
// Import modules that are useful to you
const { BIP322, Signer, Verifier } = require('bip322-js');

// Signing a BIP-322 signature with a private key
const privateKey = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
const address = 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l';
const message = 'Hello World';
const signature = Signer.sign(privateKey, address, message);
console.log(signature);

// Verifying a simple BIP-322 signature
const validity = Verifier.verifySignature(address, message, signature);
console.log(validity); // True

// You can also get the raw unsigned BIP-322 toSpend and toSign transaction directly
const scriptPubKey = Buffer.from('00142b05d564e6a7a33c087f16e0f730d1440123799d', 'hex');
const toSpend = BIP322.buildToSpendTx(message, scriptPubKey); // bitcoin.Transaction
const toSpendTxId = toSpend.getId();
const toSign = BIP322.buildToSignTx(toSpendTxId, scriptPubKey); // bitcoin.Psbt
// Do whatever you want to do with the PSBT
```

More working examples can be found within the unit test for BIP322, Signer, and Verifier.

## Getting Started
### Build Docker Image
```
docker build -t bip322-js .
```
### Run Docker Container
```
docker run -p 3000:3000 -d bip322-js
```
### sign  
Please make sure to replace the respective parameters with your own parameters.  
```
curl -X POST -H "Content-Type: application/json" -d '{"privateKey": "L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k", "address": "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l", "message": "Hello World"}' http://localhost:3000/sign
```
### verify
Please make sure to replace the respective parameters with your own parameters.  
```
curl -X POST -H "Content-Type: application/json" -d '{
  "signerAddress": "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
  "message": "Hello World",
  "signatureBase64": "AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy"
}' http://localhost:3000/verifySignature
```