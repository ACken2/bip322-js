// Import dependencies
import { expect, use } from 'chai';
import chaibytes from "chai-bytes";

// Import module to be tested
import { VarStr } from '../../src/helpers';

describe('VarStr Test', () => {

    before(() => {
        use(chaibytes);
    });

    it('Encode and decode VarStr correctly', () => {
        const toEncode = 'Hello World';
        const toEncodeBuffer = Buffer.from(toEncode, 'ascii');
        const encodedVarStr = VarStr.encode(toEncodeBuffer);
        expect(encodedVarStr).to.equalBytes([toEncode.length].concat(...toEncodeBuffer));
        const decodedStr = VarStr.decode(encodedVarStr).toString('ascii');
        expect(decodedStr).to.equal(toEncode);
    });

});