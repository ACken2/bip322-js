// Import dependencies
import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import * as bitcoinMessage from 'bitcoinjs-message';

// Import module to be tested
import { Signer } from '../src';

describe('Signer Test', () => {

    it('Can sign legacy P2PKH signature', () => {
        // Arrange
        const privateKey = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
        const privateKeyTestnet = 'cTrF79uahxMC7bQGWh2931vepWPWqS8KtF8EkqgWwv3KMGZNJ2yP'; // Equivalent to L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k
        const address = '14vV3aCHBeStb5bkenkNHbe2YAFinYdXgc';
        const addressTestnet = 'mjSSLdHFzft9NC5NNMik7WrMQ9rRhMhNpT';
        const addressRegtest = 'mjSSLdHFzft9NC5NNMik7WrMQ9rRhMhNpT';
        const message = 'Hello World';

        // Act
        const signature = Signer.sign(privateKey, address, message);
        const signatureTestnet = Signer.sign(privateKeyTestnet, addressTestnet, message, bitcoin.networks.testnet);
        const signatureRegtest = Signer.sign(privateKeyTestnet, addressRegtest, message, bitcoin.networks.regtest);

        // Assert
        expect(bitcoinMessage.verify(message, address, signature)).to.be.true;
        expect(bitcoinMessage.verify(message, addressTestnet, signatureTestnet)).to.be.true;
        expect(bitcoinMessage.verify(message, addressRegtest, signatureRegtest)).to.be.true;
    });

    it('Can sign BIP-322 signature using nested segwit address', () => {
        // Arrange
        const privateKey = 'KwTbAxmBXjoZM3bzbXixEr9nxLhyYSM4vp2swet58i19bw9sqk5z'; // Private key of "3HSVzEhCFuH9Z3wvoWTexy7BMVVp3PjS6f"
        const privateKeyTestnet = 'cMpadsm2xoVpWV5FywY5cAeraa1PCtSkzrBM45Ladpf9rgDu6cMz'; // Equivalent to 'KwTbAxmBXjoZM3bzbXixEr9nxLhyYSM4vp2swet58i19bw9sqk5z'
        const address = '3HSVzEhCFuH9Z3wvoWTexy7BMVVp3PjS6f';
        const addressTestnet = '2N8zi3ydDsMnVkqaUUe5Xav6SZqhyqEduap';
        const addressRegtest = '2N8zi3ydDsMnVkqaUUe5Xav6SZqhyqEduap';
        const message = 'Hello World';
        const expectedSignature = 'AkgwRQIhAMd2wZSY3x0V9Kr/NClochoTXcgDaGl3OObOR17yx3QQAiBVWxqNSS+CKen7bmJTG6YfJjsggQ4Fa2RHKgBKrdQQ+gEhAxa5UDdQCHSQHfKQv14ybcYm1C9y6b12xAuukWzSnS+w';

        // Act
        const signature = Signer.sign(privateKey, address, message);
        const signatureTestnet = Signer.sign(privateKeyTestnet, addressTestnet, message, bitcoin.networks.testnet);
        const signatureRegtest = Signer.sign(privateKeyTestnet, addressRegtest, message, bitcoin.networks.regtest);

        // Assert
        expect(signature).to.equal(expectedSignature);
        expect(signatureTestnet).to.equal(expectedSignature);
        expect(signatureRegtest).to.equal(expectedSignature);
    });

    it('Can sign BIP-322 signature using native segwit address', () => {
        // Arrange
        // Test vector listed at https://github.com/bitcoin/bitcoin/blob/29b28d07fa958b89e1c7916fda5d8654474cf495/src/test/util_tests.cpp#L2713
        const privateKey = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
        const privateKeyTestnet = 'cTrF79uahxMC7bQGWh2931vepWPWqS8KtF8EkqgWwv3KMGZNJ2yP'; // Equivalent to L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k
        const address = 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l';
        const addressTestnet = 'tb1q9vza2e8x573nczrlzms0wvx3gsqjx7vaxwd45v';
        const addressRegtest = 'bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vay85cr9';
        const message = 'Hello World';
        const expectedSignature = 'AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy';

        // Act
        const signature = Signer.sign(privateKey, address, message);
        const signatureTestnet = Signer.sign(privateKeyTestnet, addressTestnet, message, bitcoin.networks.testnet);
        const signatureRegtest = Signer.sign(privateKeyTestnet, addressRegtest, message, bitcoin.networks.regtest);

        // Assert
        expect(signature).to.equal(expectedSignature);
        expect(signatureTestnet).to.equal(expectedSignature);
        expect(signatureRegtest).to.equal(expectedSignature);
    });

    it('Can sign BIP-322 using single-key-spend taproot address', () => {
        // Arrange
        // Test vector listed at https://github.com/bitcoin/bitcoin/blob/29b28d07fa958b89e1c7916fda5d8654474cf495/src/test/util_tests.cpp#L2747
        const privateKey = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
        const privateKeyTestnet = 'cTrF79uahxMC7bQGWh2931vepWPWqS8KtF8EkqgWwv3KMGZNJ2yP'; // Equivalent to L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k
        const address = "bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3";
        const addressTestnet = 'tb1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5s3g3s37';
        const addressRegtest = 'bcrt1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5su3mkyy';
        const message = "Hello World";
        const expectedSignature = "AUHd69PrJQEv+oKTfZ8l+WROBHuy9HKrbFCJu7U1iK2iiEy1vMU5EfMtjc+VSHM7aU0SDbak5IUZRVno2P5mjSafAQ==";

        // Act
        const signature = Signer.sign(privateKey, address, message);
        const signatureTestnet = Signer.sign(privateKeyTestnet, addressTestnet, message, bitcoin.networks.testnet);
        const signatureRegtest = Signer.sign(privateKeyTestnet, addressRegtest, message, bitcoin.networks.regtest);

        // Assert
        expect(signature).to.equal(expectedSignature);
        expect(signatureTestnet).to.equal(expectedSignature);
        expect(signatureRegtest).to.equal(expectedSignature);
    });

    it('Throw when the provided private key cannot derive the given signing address', () => {
        // Arrange
        const privateKey = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
        const p2pkhAddressWrong = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2';
        const p2shAddressWrong = '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy';
        const p2wpkhAddressWrong = 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq';
        const p2trAddressWrong = 'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297';
        const message = 'Hello World';

        // Act
        const signP2PKH = Signer.sign.bind(Signer, privateKey, p2pkhAddressWrong, message);
        const signP2SH = Signer.sign.bind(Signer, privateKey, p2shAddressWrong, message);
        const signP2WPKH = Signer.sign.bind(Signer, privateKey, p2wpkhAddressWrong, message);
        const signP2TR = Signer.sign.bind(Signer, privateKey, p2trAddressWrong, message);

        // Assert
        expect(signP2PKH).to.throws(`Invalid private key provided for signing message for ${p2pkhAddressWrong}.`)
        expect(signP2SH).to.throws(`Invalid private key provided for signing message for ${p2shAddressWrong}.`)
        expect(signP2WPKH).to.throws(`Invalid private key provided for signing message for ${p2wpkhAddressWrong}.`)
        expect(signP2TR).to.throws(`Invalid private key provided for signing message for ${p2trAddressWrong}.`)
    });

    it('Throw when attempting to sign BIP-322 signature using unsupported address type', () => {
        // Arrange
        const privateKey = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
        const p2wshAddress = 'bc1qeklep85ntjz4605drds6aww9u0qr46qzrv5xswd35uhjuj8ahfcqgf6hak';
        const message = 'Hello World';

        // Act
        const signP2WSH = Signer.sign.bind(Signer, privateKey, p2wshAddress, message);

        // Assert
        expect(signP2WSH).to.throws('Unable to sign BIP-322 message for unsupported address type.');
    });

});