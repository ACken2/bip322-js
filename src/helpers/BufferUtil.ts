/**
 * Class that implement Buffer-related utility functions.
 */
class BufferUtil {

    /**
     * Ensures the input is a Node.js Buffer.
     * If the input is already a Buffer, it is returned unchanged.
     * Otherwise, it wraps the Uint8Array with Buffer.from.
     *
     * This is useful when working with code that may use polyfilled
     * Buffer-like objects in environments like the browser.
     *
     * @param val - The value to normalize as a Buffer.
     * @returns A Buffer instance containing the same data.
     */
    public static ensureBuffer(val: Uint8Array | Buffer): Buffer {
        return Buffer.isBuffer(val) ? val : Buffer.from(val);
    }

}

export default BufferUtil;