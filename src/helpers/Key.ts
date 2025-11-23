import { secp256k1 } from '@noble/curves/secp256k1.js';

/**
 * Class that implement key-related utility functions.
 */
class Key {

    /**
     * Converts a 33-byte Bitcoin public key to a 32-byte x-only public key as used in Taproot.
     * This function checks if the provided public key buffer is already 32 bytes long, 
     * in which case it returns the buffer unchanged. If the buffer is 33 bytes long, it 
     * assumes that the first byte is the parity byte used for indicating the y-coordinate
     * in traditional SEC1 encoding and removes this byte, thereby converting the public key 
     * to an x-only format suitable for use with Bitcoin's Taproot.
     * 
     * Adopted from https://github.com/ACken2/bip322-js/pull/6 by Czino
     *
     * @param publicKey The buffer containing the 33-byte or 32-byte public key to be converted.
     * @returns A 32-byte buffer of the x-only public key.
     * @throws If the public key is neither 32-byte nor 33-byte long
     */
    public static toXOnly(publicKey: Buffer) {
        // Throw if the input key length is invalid
        if (publicKey.length !== 32 && publicKey.length !== 33) {
            throw new Error("Invalid public key length");
        }
        // Otherwise, return the key (with the first byte removed if it is 33-byte long)
        return Buffer.from(publicKey.length === 32 ? publicKey : publicKey.subarray(1, 33));
    }

    /**
     * Compresses an uncompressed public key using the elliptic curve secp256k1.
     * This method takes a public key in its uncompressed form and returns a compressed
     * representation of the public key. Elliptic curve public keys can be represented in 
     * a shorter form known as compressed format which saves space and still retains the 
     * full public key's capabilities.
     * 
     * The steps involved in the process are:
     * 1. Parse the uncompressed public key bytes into a secp256k1 Point object.
     * 2. Serialize the Point into its compressed binary format.
     * 3. Return the compressed public key as a Buffer object.
     * 
     * @param uncompressedPublicKey A Buffer containing the uncompressed public key.
     * @return Buffer Returns a Buffer containing the compressed public key.
     * @throws Error Throws an error if the provided public key cannot be compressed,
     * typically indicating that the key is not valid.
     */
    public static compressPublicKey(uncompressedPublicKey: Buffer): Buffer {
        // Try to compress the provided public key
        try {
            // Create a key pair from the uncompressed public key buffer
            const point = secp256k1.Point.fromBytes(Buffer.from(uncompressedPublicKey));
            // Get the compressed public key as a Buffer
            const compressedPublicKey = Buffer.from(point.toBytes(true));
            return compressedPublicKey;
        }
        catch (err) {
            throw new Error('Fails to compress the provided public key. Please check if the provided key is a valid uncompressed public key.');
        }
    }

    /**
     * Uncompresses a given public key using the elliptic curve secp256k1.
     * This method accepts a compressed public key and attempts to convert it into its
     * uncompressed form. Public keys are often compressed to save space, but certain
     * operations require the full uncompressed key.
     *
     * The function operates as follows:
     * 1. Parse the compressed public key bytes into a secp256k1 Point object.
     * 2. Serialize the Point into its uncompressed binary format.
     * 3. Return the uncompressed public key as a Buffer object.
     * If the compressed public key provided is invalid and cannot be uncompressed, 
     * the method will throw an error with a descriptive message.
     * 
     * @param compressedPublicKey A Buffer containing the compressed public key.
     * @return Buffer The uncompressed public key as a Buffer.
     * @throws Error Throws an error if the provided public key cannot be uncompressed,
     * typically indicating that the key is not valid.
     */
    public static uncompressPublicKey(compressedPublicKey: Buffer): Buffer {
        // Try to uncompress the provided public key
        try {
            // Create a key pair from the compressed public key buffer
            const point = secp256k1.Point.fromBytes(Buffer.from(compressedPublicKey));
            // Get the compressed public key as a Buffer
            const uncompressedPublicKey = Buffer.from(point.toBytes(false)); // false = uncompressed
            return uncompressedPublicKey;
        }
        catch (err) {
            throw new Error('Fails to uncompress the provided public key. Please check if the provided key is a valid compressed public key.');
        }
    }

}

export default Key;