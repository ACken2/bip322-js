// Import dependencies
import { expect, use } from 'chai';
import chaibytes from "chai-bytes";

// Import module to be tested
import Helper from '../src/Helper';

describe('Helper Test', () => {

    before(() => {
        use(chaibytes);
    });

    it('Encode numebr into VarInt correctly', () => {
        expect(Helper.encodeVarInt(0x00)).to.equalBytes([0x00]);
        expect(Helper.encodeVarInt(0xF0)).to.equalBytes([0xF0]);
        expect(Helper.encodeVarInt(0xFD)).to.equalBytes([0xFD, 0xFD, 0x00]);
        expect(Helper.encodeVarInt(0xFF00)).to.equalBytes([0xFD, 0x00, 0xFF]);
        expect(Helper.encodeVarInt(0xFFFF)).to.equalBytes([0xFD, 0xFF, 0xFF]);
        expect(Helper.encodeVarInt(0x10000)).to.equalBytes([0xFE, 0x00, 0x00, 0x01, 0x00]);
        expect(Helper.encodeVarInt(0xFFFF0000)).to.equalBytes([0xFE, 0x00, 0x00, 0xFF, 0xFF]);
        expect(Helper.encodeVarInt(0xFFFFFFFF)).to.equalBytes([0xFE, 0xFF, 0xFF, 0xFF, 0xFF]);
        expect(Helper.encodeVarInt(0x100000000)).to.equalBytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        expect(Helper.encodeVarInt(0x0000FFFF00000000)).to.equalBytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00]);
        expect(Helper.encodeVarInt.bind(0x1000000000000)).to.throw(/Integer too large: /);
    });

    it('Decode VarInt into number correctly', () => {
        expect(Helper.readVarInt(Buffer.from([0x00]))).to.equal(0x00);
        expect(Helper.readVarInt(Buffer.from([0xF0]))).to.equal(0xF0);
        expect(Helper.readVarInt(Buffer.from([0xFD, 0xFD, 0x00]))).to.equal(0xFD);
        expect(Helper.readVarInt(Buffer.from([0xFD, 0x00, 0xFF]))).to.equal(0xFF00);
        expect(Helper.readVarInt(Buffer.from([0xFD, 0xFF, 0xFF]))).to.equal(0xFFFF);
        expect(Helper.readVarInt(Buffer.from([0xFE, 0x00, 0x00, 0x01, 0x00]))).to.equal(0x10000);
        expect(Helper.readVarInt(Buffer.from([0xFE, 0x00, 0x00, 0xFF, 0xFF]))).to.equal(0xFFFF0000);
        expect(Helper.readVarInt(Buffer.from([0xFE, 0xFF, 0xFF, 0xFF, 0xFF]))).to.equal(0xFFFFFFFF);
        expect(Helper.readVarInt(Buffer.from([0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]))).to.equal(0x100000000);
        expect(Helper.readVarInt(Buffer.from([0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00]))).to.equal(0x0000FFFF00000000);
    });

    it('Encode and decode VarStr correctly', () => {
        const toEncode = 'Hello World';
        const toEncodeBuffer = Buffer.from(toEncode, 'ascii');
        const encodedVarStr = Helper.encodeVarStr(toEncodeBuffer);
        expect(encodedVarStr).to.equalBytes([toEncode.length].concat(...toEncodeBuffer));
        const decodedStr = Helper.readVarStr(encodedVarStr).toString('ascii');
        expect(decodedStr).to.equal(toEncode);
    });

});