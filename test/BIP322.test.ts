// Import dependencies
import ECPairFactory from 'ecpair';
import * as bitcoin from 'bitcoinjs-lib';
import ecc from '@bitcoinerlab/secp256k1';
import { expect } from 'chai';

// Import module to be tested
import BIP322 from "../src/BIP322";

// Tests
describe('BIP322 Test', () => {

    it('Produce correct message hash', () => {
        // Test vector listed at https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#user-content-Message_hashing
        const emptyStringHash = Buffer.from(BIP322.hashMessage("")).toString('hex').toLowerCase();
        expect(emptyStringHash).to.equal("c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1");
        const helloWorldHash = Buffer.from(BIP322.hashMessage("Hello World")).toString('hex').toLowerCase();
        expect(helloWorldHash).to.equal("f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a");
    });

    it('Draft correct BIP-322 toSpend transaction', () => {
        // Test vector listed at https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#user-content-Transaction_Hashes
        // Obtain the script public key
        const scriptPubKey = bitcoin.payments.p2wpkh({
			address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l"
		}).output as Buffer;
        // Draft a toSpend transaction with empty message
        const emptyStringToSpendTx = BIP322.buildToSpendTx("", scriptPubKey);
        expect(emptyStringToSpendTx.getId().toLowerCase()).to.equal("c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7");
        // Draft a toSpend transaction with Hello World
        const helloWorldToSpendTx = BIP322.buildToSpendTx("Hello World", scriptPubKey);
        expect(helloWorldToSpendTx.getId().toLowerCase()).to.equal("b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b");
    });

    it('Draft correct BIP-322 toSign transaction', () => {
        // Test vector listed at https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#user-content-Transaction_Hashes
        // Obtain the script public key
        const scriptPubKey = bitcoin.payments.p2wpkh({
			address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l"
		}).output as Buffer;
        // Initialize private key used to sign the transaction
        const ECPair = ECPairFactory(ecc);
        const testPrivateKey = ECPair.fromWIF(
			'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k',
		);
        // Draft a toSign transaction with empty message
        const emptyStringToSpendTxId = "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7";
        const emptyStringToSignTx = BIP322.buildToSignTx(emptyStringToSpendTxId, scriptPubKey);
        const emptyStringToSignTxSigned = emptyStringToSignTx.signAllInputs(testPrivateKey).finalizeAllInputs().extractTransaction();
        expect(emptyStringToSignTxSigned.getId().toLowerCase()).to.equal("1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6");
        // Draft a toSign transaction with Hello World
        const helloWorldToSpendTxId = "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b";
        const helloWorldToSignTx = BIP322.buildToSignTx(helloWorldToSpendTxId, scriptPubKey);
        const helloWorldToSignTxSigned = helloWorldToSignTx.signAllInputs(testPrivateKey).finalizeAllInputs().extractTransaction();
        expect(helloWorldToSignTxSigned.getId().toLowerCase()).to.equal("88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf");
    });

    it('Encode witness into signature correctly', () => {
        // Test vector listed at https://github.com/bitcoin/bitcoin/blob/29b28d07fa958b89e1c7916fda5d8654474cf495/src/test/util_tests.cpp#L2713
        // Obtain the script public key
        const scriptPubKey = bitcoin.payments.p2wpkh({
			address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l"
		}).output as Buffer;
        // Initialize private key used to sign the transaction
        const ECPair = ECPairFactory(ecc);
        const testPrivateKey = ECPair.fromWIF(
			'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k',
		);
        // Draft a toSign transaction with Hello World
        const toSpendTxId = "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b";
        const toSignTx = BIP322.buildToSignTx(toSpendTxId, scriptPubKey);
        const toSignTxSigned = toSignTx.signAllInputs(testPrivateKey).finalizeAllInputs().extractTransaction();
        // Extract the witness information and encode it as a BIP-322 signature
        const signature = BIP322.encodeWitness(toSignTxSigned.ins[0].witness);
        expect(signature).to.equal("AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy");
    });

});