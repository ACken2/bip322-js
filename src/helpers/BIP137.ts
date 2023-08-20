// Import dependencies
import ecc from 'secp256k1';
import * as bitcoinMessage from 'bitcoinjs-message';

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
    public static derivePubKey(message: string, signature: string) {
        // Compute the hash signed by the signer
        const messageHash = bitcoinMessage.magicHash(message);
        // Decode the provided BIP-137 signature
        const signatureDecoded = this.decodeSignature(Buffer.from(signature, 'base64'));
        // Recover the public key
        return Buffer.from(ecc.ecdsaRecover(signatureDecoded.signature, signatureDecoded.recovery, messageHash, signatureDecoded.compressed));
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
            signature: signature.subarray(1)
        }
    }

}

export default BIP137;