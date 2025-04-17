// Import dependencies
import { expect } from 'chai';

// Import module to be tested
import { BufferUtil } from '../../src/helpers';

describe('BufferUtil.ensureBuffer', () => {

    it('Return the same Buffer instance if input is already a Buffer', () => {
        const buf = Buffer.from([1, 2, 3]);
        const result = BufferUtil.ensureBuffer(buf);
        expect(result).to.equal(buf); // same reference
    });

    it('Convert a Uint8Array to a Buffer with identical contents', () => {
        const uint8 = new Uint8Array([4, 5, 6]);
        const result = BufferUtil.ensureBuffer(uint8);
        expect(Buffer.isBuffer(result)).to.be.true;
        expect(result.equals(Buffer.from([4, 5, 6]))).to.be.true;
    });

});