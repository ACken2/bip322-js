// Import dependency
import VarInt from "./VarInt";
import BufferUtil from "./BufferUtil";

/**
 * Class that implement variable length string (VarStr) in Javascript. 
 * Reference: https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_string
 */
class VarStr {

    /**
     * Encode a string buffer as a variable length string.
     * Reference: https://github.com/buidl-bitcoin/buidl-python/blob/d79e9808e8ca60975d315be41293cb40d968626d/buidl/helper.py#L203
     * @param s String buffer to be encoded
     * @returns Encoded varstr
     */
    public static encode(s: Buffer) {
        // Encode the length of the string using encodeVarInt
        const lengthBuffer = VarInt.encode(s.length);
        // Concat the actual string right after the length of the string
        return Buffer.concat([lengthBuffer, s]);
    }

    /**
     * Decode a variable length string from a Buffer into a string buffer.
     * Reference: https://github.com/buidl-bitcoin/buidl-python/blob/d79e9808e8ca60975d315be41293cb40d968626d/buidl/helper.py#L194
     * @param v Varstr to be decoded
     * @returns Decoded string buffer
     */
    public static decode(v: Buffer) {
        // Find the length of the string by using read_varint on the string
        const length = VarInt.decode(v);
        // Get the length of the VarInt used to represent the length of the string
        const lengthByteLength = VarInt.encode(length).byteLength;
        // Return from lengthByteLength to (length + lengthByteLength) in the buffer which contain the actual string
        return BufferUtil.ensureBuffer(v.subarray(lengthByteLength, length + lengthByteLength));
    }

}

export default VarStr;