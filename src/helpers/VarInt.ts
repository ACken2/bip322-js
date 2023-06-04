/**
 * Class that implement variable length integer (VarInt) in Javascript. 
 * Reference: https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
 */
class VarInt {

    /**
     * Encode an integer i as a variable length integer.
     * Reference: https://github.com/buidl-bitcoin/buidl-python/blob/d79e9808e8ca60975d315be41293cb40d968626d/buidl/helper.py#L180
     * @param i Integer to be encoded
     * @returns Encoded varint
     */
    public static encode(i: number) {
        if (i < 0xFD) {
            const buffer = Buffer.alloc(1);
            buffer.writeUInt8(i);
            return buffer;
        }
        else if (i < 0x10000) {
            const buffer = Buffer.alloc(3);
            buffer.writeUInt8(0xfd);
            buffer.writeUInt16LE(i, 1);
            return buffer;
        }
        else if (i < 0x100000000) {
            const buffer = Buffer.alloc(5);
            buffer.writeUInt8(0xfe);
            buffer.writeUInt32LE(i, 1);
            return buffer;
        }
        else if (i < 0x1000000000000) {
            const buffer = Buffer.alloc(9);
            buffer.writeUInt8(0xff);
            buffer.writeUIntLE(i, 1, 6); // Cannot write UInt64LE in Node JS
            buffer.writeUInt8(0x00, 7); // Pad two extra 0x00 at the end to emulate UInt64LE
            buffer.writeUInt8(0x00, 8);
            return buffer;
        }
        else {
            throw new Error(`Integer too large: ${i}`);
        }
    }

    /**
     * Decode a variable length integer from a Buffer into a number.
     * Reference: https://github.com/buidl-bitcoin/buidl-python/blob/d79e9808e8ca60975d315be41293cb40d968626d/buidl/helper.py#L160
     * @param b Buffer which contain the varint
     * @returns Decoded number
     */
    public static decode(b: Buffer) {
        // Check for empty buffer
        if (b.byteLength === 0) {
            throw new Error('Empty buffer provided');
        }
        // Read first byte from the buffer
        const i = b.readUInt8();
        // Check if i is indicating its length
        if (i === 0xfd) {
            // 0xfd means the next two bytes are the number
            return b.readUInt16LE(1);
        }
        else if (i === 0xfe) {
            // 0xfe means the next four bytes are the number
            return b.readUInt32LE(1);
        }
        else if (i === 0xff) {
            // 0xff means the next eight bytes are the number, but Node JS can only read up to 6 bytes
            return b.readUIntLE(1, 6);
        }
        else {
            // Anything else is just the integer
            return i;
        }
    }

}

export default VarInt;