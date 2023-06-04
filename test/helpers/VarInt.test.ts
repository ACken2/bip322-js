// Import dependencies
import { expect, use } from 'chai';
import chaibytes from "chai-bytes";

// Import module to be tested
import { VarInt } from '../../src/helpers';

describe('VarInt Test', () => {

    before(() => {
        use(chaibytes);
    });

    it('Encode numebr into VarInt correctly', () => {
        expect(VarInt.encode(0x00)).to.equalBytes([0x00]);
        expect(VarInt.encode(0xF0)).to.equalBytes([0xF0]);
        expect(VarInt.encode(0xFD)).to.equalBytes([0xFD, 0xFD, 0x00]);
        expect(VarInt.encode(0xFF00)).to.equalBytes([0xFD, 0x00, 0xFF]);
        expect(VarInt.encode(0xFFFF)).to.equalBytes([0xFD, 0xFF, 0xFF]);
        expect(VarInt.encode(0x10000)).to.equalBytes([0xFE, 0x00, 0x00, 0x01, 0x00]);
        expect(VarInt.encode(0xFFFF0000)).to.equalBytes([0xFE, 0x00, 0x00, 0xFF, 0xFF]);
        expect(VarInt.encode(0xFFFFFFFF)).to.equalBytes([0xFE, 0xFF, 0xFF, 0xFF, 0xFF]);
        expect(VarInt.encode(0x100000000)).to.equalBytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        expect(VarInt.encode(0x0000FFFF00000000)).to.equalBytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00]);
        expect(VarInt.encode.bind(0x1000000000000)).to.throw(/Integer too large: /);
    });

    it('Decode VarInt into number correctly', () => {
        expect(VarInt.decode(Buffer.from([0x00]))).to.equal(0x00);
        expect(VarInt.decode(Buffer.from([0xF0]))).to.equal(0xF0);
        expect(VarInt.decode(Buffer.from([0xFD, 0xFD, 0x00]))).to.equal(0xFD);
        expect(VarInt.decode(Buffer.from([0xFD, 0x00, 0xFF]))).to.equal(0xFF00);
        expect(VarInt.decode(Buffer.from([0xFD, 0xFF, 0xFF]))).to.equal(0xFFFF);
        expect(VarInt.decode(Buffer.from([0xFE, 0x00, 0x00, 0x01, 0x00]))).to.equal(0x10000);
        expect(VarInt.decode(Buffer.from([0xFE, 0x00, 0x00, 0xFF, 0xFF]))).to.equal(0xFFFF0000);
        expect(VarInt.decode(Buffer.from([0xFE, 0xFF, 0xFF, 0xFF, 0xFF]))).to.equal(0xFFFFFFFF);
        expect(VarInt.decode(Buffer.from([0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]))).to.equal(0x100000000);
        expect(VarInt.decode(Buffer.from([0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00]))).to.equal(0x0000FFFF00000000);
    });

});