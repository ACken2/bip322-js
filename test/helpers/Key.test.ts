// Import dependencies
import { expect, use } from 'chai';
import chaibytes from 'chai-bytes';

// Import module to be tested
import { Key } from '../../src';

describe('Key Test', () => {

    before(() => {
        use(chaibytes);
    });

    describe('Public Key toXOnly', () => {

        it('Return the same 32-byte buffer if input key is already 32 bytes', () => {
            // Arrange
            const inputKey = Buffer.from('f7fb07050d858b3289c2a0305fbac1f5b18233798665c0cbfe133e018b57cafc', 'hex'); // 32-byte public key
            // Act
            const outputKey = Key.toXOnly(inputKey);
            // Assert
            expect(outputKey).to.equalBytes(inputKey);
        });
        
          it('Convert a 33-byte public key to a 32-byte x-only public key', () => {
            // Arrange
            const inputKey = Buffer.from('02f7fb07050d858b3289c2a0305fbac1f5b18233798665c0cbfe133e018b57cafc', 'hex'); // 33-byte public key
            const expectedOutputKey = Buffer.from('f7fb07050d858b3289c2a0305fbac1f5b18233798665c0cbfe133e018b57cafc', 'hex'); // Expected 32-byte key
            // Act
            const outputKey = Key.toXOnly(inputKey);
            // Assert
            expect(outputKey).to.equalBytes(expectedOutputKey);
        });
        
        it('Throw when encountering a non-standard key buffer', () => {
            // Arrange
            const inputKey = Buffer.from('fb07050d858b3289c2a0305fbac1f5b18233798665c0cbfe133e018b57cafc', 'hex'); // 31-byte public key
            // Act
            const result = Key.toXOnly.bind(Key, inputKey);
            // Arrange
            expect(result).to.throws('Invalid public key length');
        });

    });

    describe('Public Key Cmpression Function', function() {

        it('Compress a uncompressed public key', function() {
            // Arrange
            const uncompressedPublicKey = Buffer.from('044bc3c1746b7f526b560517a61f2fad554c24d6a457503e4ec7e69f817f68599f04edf9e6ea7e0796a176fba3957560f307e4c49cb2a46b4969e710f5933e700e', 'hex');
            const compressedPublicKey = Buffer.from('024bc3c1746b7f526b560517a61f2fad554c24d6a457503e4ec7e69f817f68599f', 'hex');
            // Act
            const compressed = Key.compressPublicKey(uncompressedPublicKey);
            // Assert
            expect(compressed).to.deep.equal(compressedPublicKey);
        });

        it('Throw with invalid uncompressed public key', function() {
            // Arrange
            const notUncompressedPublicKey = Buffer.from('024bc3c1746b7f526b560517a61f2fad554c24d6a457503e4ec7e69f817f68599f', 'hex');
            const notUncompressedPublicKeyAsWell = Buffer.from('044bc3c1746b7f526b560517a61f2fad554c24d6a457503e4ec7e69f817f68599f04edf9e6ea7e0796a176fba3957560f307e4c49cb2a46b4969e710f5933e700f', 'hex');
            // Act
            const compressAttempt = Key.compressPublicKey.bind(notUncompressedPublicKey);
            const compressAttemptTwo = Key.compressPublicKey.bind(notUncompressedPublicKeyAsWell);
            // Assert
            expect(compressAttempt).to.throws('Fails to compress the provided public key. Please check if the provided key is a valid uncompressed public key.');
            expect(compressAttemptTwo).to.throws('Fails to compress the provided public key. Please check if the provided key is a valid uncompressed public key.');
        });

        it('Uncompress a compressed public key', function() {
            // Arrange
            const uncompressedPublicKey = Buffer.from('044bc3c1746b7f526b560517a61f2fad554c24d6a457503e4ec7e69f817f68599f04edf9e6ea7e0796a176fba3957560f307e4c49cb2a46b4969e710f5933e700e', 'hex');
            const compressedPublicKey = Buffer.from('024bc3c1746b7f526b560517a61f2fad554c24d6a457503e4ec7e69f817f68599f', 'hex');
            // Act
            const uncompressed = Key.uncompressPublicKey(compressedPublicKey);
            // Assert
            expect(uncompressed).to.deep.equal(uncompressedPublicKey);
        });

        it('Throw with invalid compressed public key', function() {
            // Arrange
            const notCompressedPublicKey = Buffer.from('044bc3c1746b7f526b560517a61f2fad554c24d6a457503e4ec7e69f817f68599f04edf9e6ea7e0796a176fba3957560f307e4c49cb2a46b4969e710f5933e700f', 'hex');
            const notCompressedPublicKeyAsWell = Buffer.from('024bc3c1746b7f526b560517a61f2fad554c24d6a457503e4ec7e69f817f68599e', 'hex');
            // Act
            const uncompressAttempt = Key.uncompressPublicKey.bind(notCompressedPublicKey);
            const uncompressAttemptTwo = Key.uncompressPublicKey.bind(notCompressedPublicKeyAsWell);
            // Assert
            expect(uncompressAttempt).to.throws('Fails to uncompress the provided public key. Please check if the provided key is a valid compressed public key.');
            expect(uncompressAttemptTwo).to.throws('Fails to uncompress the provided public key. Please check if the provided key is a valid compressed public key.');
        });

    });

});