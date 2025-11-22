// Import dependencies
import BufferUtil from './BufferUtil';
import BitcoinMessage from './BitcoinMessage';
import { secp256k1 } from '@noble/curves/secp256k1.js';

/**
 * Class that implement BIP137-related utility functions.
 */
class BIP137 {

    /**
     * Check if a given signature satisified the format of a BIP-137 signature.
     * @param signature Base64-encoded signature to be checked
     * @returns True if the provided signature correspond to a valid BIP-137 signature, false if otherwise
     */
    public static isBIP137Signature(signature: string) {
        // Check if the provided signature satisified the format of a BIP-137 signature
        const signatureBuffer = Buffer.from(signature, 'base64');
        if (signatureBuffer.byteLength === 65) {
            return true;
        }
        else {
            return false;
        }
    }

    /**
     * Derive the public key that signed a valid BIP-137 signature.
     * @param message Message signed by the signature
     * @param signature Base-64 encoded signature to be decoded
     * @returns Public key that signs the provided signature
     */
    public static derivePubKey(message: string | Buffer, signature: string) {
        // Compute the hash signed by the signer
        const messageHash = BitcoinMessage.magicHash(message);
        // Decode the provided BIP-137 signature
        const signatureDecoded = this.decodeSignature(Buffer.from(signature, 'base64'));
        // Slice the 64-byte signature into r and s
        // Note: BIP-137 signatureDecoded.signature is 64 bytes (r + s)
        const r = BigInt('0x' + signatureDecoded.signature.subarray(0, 32).toString('hex'));
        const s = BigInt('0x' + signatureDecoded.signature.subarray(32, 64).toString('hex'));
        // Construct the Signature and add the recovery bit
        const sig = new secp256k1.Signature(r, s).addRecoveryBit(signatureDecoded.recovery);
        // 3. Recover the public key
        const point = sig.recoverPublicKey(messageHash);
        // Convert Point -> Buffer (using the compressed flag from the decoded signature)
        return Buffer.from(point.toBytes(signatureDecoded.compressed));
    }

    /**
     * Decode a BIP-137 signature.
     * Function copied from bitcoinjs-message library.
     * @param signature BIP-137 signature to be decoded
     * @returns Decoded BIP-137 signature
     */
    private static decodeSignature(signature: Buffer) {
        if (signature.length !== 65) throw new Error('Invalid signature length');
        const flagByte = signature.readUInt8(0) - 27;
        if (flagByte > 19 || flagByte < 0) {
            throw new Error('Invalid signature parameter');
        }
        return {
            compressed: !!(flagByte & 12),
            recovery: flagByte & 3,
            signature: BufferUtil.ensureBuffer(signature.subarray(1))
        }
    }

}

export default BIP137;