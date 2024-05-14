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

});