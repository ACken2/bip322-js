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

}

export default Key;