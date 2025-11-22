import BIP137 from './BIP137';
import VarInt from './VarInt';
import { sha256 } from '@noble/hashes/sha2.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { payments, address as bjsAddress, networks } from 'bitcoinjs-lib';

// Mimic bitcoinjs-message options
interface SignOptions {
    segwitType?: 'p2sh(p2wpkh)' | 'p2wpkh';
    extraEntropy?: Buffer;
}

/**
 * Drop-in replacement class for bitcoinjs-message.
 */
class BitcoinMessage {

    /**
     * Signs a message with full BIP-137 support, compatible with Legacy (P2PKH),
     * Nested Segwit (P2SH-P2WPKH), and Native Segwit (P2WPKH) addresses.
     *
     * This method produces a compact signature using the secp256k1 elliptic curve.
     * It implements deterministic signatures (RFC 6979) by default but supports
     * additional entropy via options. The resulting signature includes a specific header
     * byte that encodes the recovery ID and the key/address type, allowing for public
     * key recovery during verification.
     * 
     * The process involves:
     * 1. Hashing the message with the Bitcoin magic prefix (double SHA-256).
     * 2. Signing the hash deterministically (or with extra entropy).
     * 3. Calculating the recovery ID (0-3) ensuring the public key matches.
     * 4. Constructing the BIP-137 header byte based on the address type and compression.
     * 5. Returning the concatenated signature buffer [header + r + s].
     *
     * @param message The message string or buffer to be signed.
     * @param privateKey The 32-byte private key buffer used for signing.
     * @param compressed Boolean indicating if the corresponding public key is compressed.
     * @param options Optional parameters including 'segwitType' ('p2sh(p2wpkh)' or 'p2wpkh') and 'extraEntropy'.
     * @returns A Buffer containing the 65-byte BIP-137 signature.
     */
    public static sign(message: string | Buffer, privateKey: Buffer, compressed: boolean, options?: SignOptions): Buffer {
        const hash = this.magicHash(message);
        
        // 1. Sign (Deterministic or with extra entropy)
        const opts = { 
            prehash: false, // Tells the secp256k1 lib to not hash it again
            extraEntropy: options?.extraEntropy 
        };
        
        const sigAny = secp256k1.sign(hash, privateKey, opts as any);

        let r: bigint, s: bigint, recovery: number;

        r = BigInt('0x' + Buffer.from(sigAny.subarray(0, 32)).toString('hex'));
        s = BigInt('0x' + Buffer.from(sigAny.subarray(32, 64)).toString('hex'));
        
        // Recalculate recovery ID
        recovery = 0;
        const pubKey = secp256k1.getPublicKey(privateKey);
        for (let i = 0; i < 4; i++) {
            try {
                const rec = new secp256k1.Signature(r, s).addRecoveryBit(i).recoverPublicKey(hash);
                if (Buffer.from(rec.toBytes(true)).equals(Buffer.from(pubKey))) {
                    recovery = i;
                    break;
                }
            } 
            catch(e) {
                // Wrong recovery bit - try again
            }
        }

        // 2. Calculate Header Byte based on Type
        let header = 27 + recovery;

        if (options?.segwitType === 'p2wpkh') {
            // Native Segwit (Bech32): 39-42
            header += 12; 
        } 
        else if (options?.segwitType === 'p2sh(p2wpkh)') {
            // Nested Segwit (P2SH): 35-38
            header += 8;
        } 
        else {
            // Legacy P2PKH: 27-34
            if (compressed) {
                header += 4;
            }
        }

        // 3. Combine [1 byte of header data][32 bytes for r value][32 bytes for s value] into BIP-137 signature
        return Buffer.concat([Buffer.from([header]), sigAny]);
    }

    /**
     * Verifies a signed Bitcoin message against a provided address.
     *
     * This method validates signatures adhering to the BIP-137 standard. It supports
     * automatic detection of the address type (Legacy, Nested Segwit, or Native Segwit)
     * and the network (Mainnet, Testnet, Regtest) by analyzing the signature header
     * and the provided address format.
     *
     * The verification steps are:
     * 1. Parse the signature header to determine the recovery ID and expected address type.
     * 2. Recover the public key from the signature and message hash.
     * 3. Convert the provided address into a network-agnostic output script.
     * 4. Derive the expected output script from the recovered public key based on the detected type.
     * 5. Compare the derived script with the target address script.
     *
     * @param message The message that was signed (string or Buffer).
     * @param address The Bitcoin address (Legacy, Segwit, or Bech32) that supposedly signed the message.
     * @param signatureBase64 The Base64 encoded signature string.
     * @returns boolean Returns true if the signature is valid for the given message and address, false otherwise.
     */
    public static verify(message: string | Buffer, address: string, signatureBase64: string): boolean {
        const signatureBuffer = Buffer.from(signatureBase64, 'base64');

        if (signatureBuffer.length !== 65) return false; // Invalid BIP-137 signature

        const header = signatureBuffer[0];

        // 1. Parse Header to determine Key Compression and Address Type
        let recId = header - 27;
        let compressed = false;
        let type: 'p2pkh' | 'p2sh(p2wpkh)' | 'p2wpkh' = 'p2pkh';

        if (header >= 39) { // Segwit Bech32
            recId -= 12;
            type = 'p2wpkh';
            compressed = true;
        } 
        else if (header >= 35) { // Segwit P2SH
            recId -= 8;
            type = 'p2sh(p2wpkh)';
            compressed = true;
        } 
        else if (header >= 31) { // Compressed P2PKH
            recId -= 4;
            compressed = true;
        } 
        else { // Uncompressed P2PKH
            compressed = false;
        }

        if (recId < 0 || recId > 3) return false;

        try {
            // 2. Recover Public Key
            const pubKey = BIP137.derivePubKey(message, signatureBase64);

            // 3. Get Target Script (Network Agnostic)
            // Automatically detect network by trying all options
            const targetScript = this.toOutputScriptAnyNetwork(address);
            if (!targetScript) return false; // Address was invalid on all networks

            // 4. Derive the Expected Output Script from the Recovered Key
            let payment: any;
            
            if (type === 'p2wpkh') {
                payment = payments.p2wpkh({ pubkey: pubKey });
            } 
            else if (type === 'p2sh(p2wpkh)') {
                payment = payments.p2sh({ 
                    redeem: payments.p2wpkh({ pubkey: pubKey }) 
                });
            } 
            else {
                // Assumed p2pkh
                // It automatically infers either a P2PKH Compressed or P2PKH Uncompressed 
                // based on the flag presented on the signature
                payment = payments.p2pkh({ pubkey: pubKey });
            }

            // 5. Compare the Scripts
            return payment.output.equals(targetScript);
        } 
        catch (e) {
            return false;
        }
    }

    /**
     * Computes the "Magic Hash" of a message as defined in the Bitcoin message signing standard.
     * 
     * The function prefixes the message with specific bytes ("\x18Bitcoin Signed Message:\n")
     * and the variable-length encoded message length, then performs a double SHA-256 hash 
     * (hash256) on the result. This specific hashing mechanism prevents the signature from 
     * being used as a valid transaction signature on the Bitcoin network.
     *
     * @param message The input message to be hashed (string or Buffer).
     * @returns Buffer A 32-byte Buffer containing the double SHA-256 hash of the prefixed message.
     */
    public static magicHash(message: string | Buffer): Buffer {
        const prefix = Buffer.from('\x18Bitcoin Signed Message:\n', 'utf8');
        const messageBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf8');
        const len = VarInt.encode(messageBuffer.length);
        const buffer = Buffer.concat([prefix, len, messageBuffer]);
        return Buffer.from(sha256(sha256(buffer)));
    }

    /**
     * Converts a Bitcoin address string into its corresponding output script buffer,
     * attempting to detect the network automatically.
     * 
     * Since `bitcoinjs-lib` enforces strict network validation (defaulting to Mainnet), this
     * helper iterates through Mainnet, Testnet, and Regtest networks to successfully
     * parse the address. This allows the verifier to handle addresses from different
     * networks transparently without requiring explicit network configuration from the caller.
     *
     * @param address The Bitcoin address string to convert.
     * @returns Buffer | null The output script Buffer if the address is valid on any supported network, or null if invalid.
     */
    private static toOutputScriptAnyNetwork(address: string): Buffer | null {
        // List of networks to try. 
        const candidates = [networks.bitcoin, networks.testnet, networks.regtest];
        for (const network of candidates) {
            try {
                return bjsAddress.toOutputScript(address, network);
            } 
            catch (e) {
                // Continue to next network if this one mismatches
            }
        }
        return null;
    }

}

export default BitcoinMessage;