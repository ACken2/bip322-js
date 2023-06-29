// Import dependencies
import { expect, use } from 'chai';
import chaibytes from "chai-bytes";

// Import module to be tested
import { Witness } from '../../src';

describe('Witness Test', () => {

    // Witness data from test vector listed at https://github.com/bitcoin/bitcoin/blob/29b28d07fa958b89e1c7916fda5d8654474cf495/src/test/util_tests.cpp#L2713
    const witnessStack = [
        Buffer.from('MEUCIQDs8sp5arfd5Tiia/sJpsSHp7P/8z85fbaiDrmvd8DujAIgYuZ+RMgHD0nDo39ZQKiFCELa98yjXmr2Gmx8kfHhoaMB', 'base64'),
        Buffer.from('AsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy', 'base64')
    ];
    const encodedWitness = 'AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy';

    before(() => {
        use(chaibytes);
    });

    it('Encode witness stack correctly', () => {
        const encoded = Witness.serialize(witnessStack);
        expect(encoded).to.equal(encodedWitness);
    });

    it('Decode encoded witness correctly when given a base-64 encoded string', () => {
        const decoded = Witness.deserialize(encodedWitness);
        expect(decoded.length).to.equal(witnessStack.length);
        for (let i=0; i<decoded.length; i++) {
            expect(decoded[i]).to.equalBytes(witnessStack[i]);
        }
    });

    it('Decode encoded witness correctly when given a Buffer', () => {
        const decoded = Witness.deserialize(Buffer.from(encodedWitness, 'base64'));
        expect(decoded.length).to.equal(witnessStack.length);
        for (let i=0; i<decoded.length; i++) {
            expect(decoded[i]).to.equalBytes(witnessStack[i]);
        }
    });

});