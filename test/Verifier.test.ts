// Import dependencies
import { expect } from 'chai';
import BIP322 from "../src/BIP322";
import ECPairFactory from 'ecpair';
import * as bitcoin from 'bitcoinjs-lib';
import ecc from '@bitcoinerlab/secp256k1';

// Import module to be tested
import Verifier from '../src/Verifier';

// Tests
describe('Verifier Test', () => {

    it('Can verify and falsify BIP-322 signature for P2SH-P2WPKH address', () => {
        // Arrange
        // Constants
        const privateKey = "L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k"; // Identical private key as bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l
        const address = "37qyp7jQAzqb2rCBpMvVtLDuuzKAUCVnJb"; // Derived from the private key above
        const addressWrong = "342ftSRCvFHfCeFFBuz4xwbeqnDw6BGUey";
        const messageWrong = "";
        const messageHelloWorld = "Hello World";
        // Initialize private key used to sign the transaction
        const ECPair = ECPairFactory(ecc);
        const testPrivateKey = ECPair.fromWIF(privateKey);
        // Obtain the script public key
        const scriptPubKey = bitcoin.payments.p2sh({
			address: address
		}).output as Buffer;
        // Derive the P2SH-P2WPKH redeemScript from the corresponding hashed public key
        const redeemScript = bitcoin.payments.p2wpkh({
			hash: bitcoin.crypto.hash160(testPrivateKey.publicKey)
		}).output as Buffer;
        // Draft a toSpend transaction with messageHelloWorld
        const toSpendTx = BIP322.buildToSpendTx(messageHelloWorld, scriptPubKey);
        // Draft a toSign transaction that spends toSpend transaction
        const toSignTx = BIP322.buildToSignTx(toSpendTx.getId(), redeemScript, true);
        // Sign the toSign transaction
        const toSignTxSigned = toSignTx.signAllInputs(testPrivateKey).finalizeAllInputs();
        // Extract the signature
        const signature = toSignTxSigned.data.inputs[0].finalScriptWitness?.toString('base64') as string;

        // Act
        const resultCorrect = Verifier.verifySignature(address, messageHelloWorld, signature); // Everything correct
        const resultWrongMessage = Verifier.verifySignature(address, messageWrong, signature); // Wrong message - should be false
        const resultWrongAddress = Verifier.verifySignature(addressWrong, messageHelloWorld, signature); // Wrong address - should be false

        // Assert
        expect(resultCorrect).to.be.true;
        expect(resultWrongMessage).to.be.false;
        expect(resultWrongAddress).to.be.false;
    });

    it('Can verify and falsify BIP-322 signature for P2WPKH address', () => {
        // Arrange
        // Test vectors listed at https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#user-content-Test_vectors
        const address = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";
        const addressWrong = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        const messageEmpty = "";
        const messageHelloWorld = "Hello World";
        const signatureEmpty = "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";
        const signatureHelloWorld = "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";
        // Additional test vector listed at https://github.com/bitcoin/bitcoin/blob/29b28d07fa958b89e1c7916fda5d8654474cf495/src/test/util_tests.cpp#L2713
        const signatureHelloWorldAlt = "AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy";
        
        // Act
        // Correct addresses and correct signature
        const resultEmptyValid = Verifier.verifySignature(address, messageEmpty, signatureEmpty);
        const resultHelloWorldValid = Verifier.verifySignature(address, messageHelloWorld, signatureHelloWorld);
        const resultHelloWorldValidII =  Verifier.verifySignature(address, messageHelloWorld, signatureHelloWorldAlt);
        // Correct addresses but incorrect signature
        const resultHelloWorldInvalidSig = Verifier.verifySignature(address, messageEmpty, signatureHelloWorld); // Mixed up the signature and message - should be false
        const resultEmptyInvalidSig = Verifier.verifySignature(address, messageHelloWorld, signatureEmpty); // Mixed up the signature and message - should be false
        // Incorrect addresses
        const resultEmptyInvalidAddress = Verifier.verifySignature(addressWrong, messageEmpty, signatureEmpty); // Wrong address - should be false
        const resultHelloWorldInvalidAddress = Verifier.verifySignature(addressWrong, messageHelloWorld, signatureHelloWorld); // Wrong address - should be false
        
        // Assert
        expect(resultEmptyValid).to.be.true;
        expect(resultHelloWorldValid).to.be.true;
        expect(resultHelloWorldValidII).to.be.true;
        expect(resultHelloWorldInvalidSig).to.be.false;
        expect(resultEmptyInvalidSig).to.be.false; 
        expect(resultEmptyInvalidAddress).to.be.false;
        expect(resultHelloWorldInvalidAddress).to.be.false;
    });

    it('Can verify and falsify BIP-322 signature for single-key-spend P2TR address', () => {
        // Arrange
        // Test vector listed at https://github.com/bitcoin/bitcoin/blob/29b28d07fa958b89e1c7916fda5d8654474cf495/src/test/util_tests.cpp#L2747
        const address = "bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3";
        const addressWrong = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
        const messageWrong = "";
        const messageHelloWorld = "Hello World";
        const signatureHelloWorld = "AUHd69PrJQEv+oKTfZ8l+WROBHuy9HKrbFCJu7U1iK2iiEy1vMU5EfMtjc+VSHM7aU0SDbak5IUZRVno2P5mjSafAQ==";

        // Act
        const resultCorrect = Verifier.verifySignature(address, messageHelloWorld, signatureHelloWorld); // Everything correct
        const resultWrongMessage = Verifier.verifySignature(address, messageWrong, signatureHelloWorld); // Wrong message - should be false
        const resultWrongAddress = Verifier.verifySignature(addressWrong, messageHelloWorld, signatureHelloWorld); // Wrong address - should be false

        // Assert
        expect(resultCorrect).to.be.true;
        expect(resultWrongMessage).to.be.false;
        expect(resultWrongAddress).to.be.false;
    });

});