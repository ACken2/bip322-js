// Import dependencies
import BIP322 from "./BIP322";
import * as bitcoin from 'bitcoinjs-lib';
import ecc from '@bitcoinerlab/secp256k1';
import { decodeScriptSignature } from './bitcoinjs';

/**
 * Class that handles BIP-322 signature verification.
 * Reference: https://github.com/LegReq/bip0322-signatures/blob/master/BIP0322_verification.ipynb
 */
class Verifier {

    /**
     * Verify a BIP-322 signature from P2WPKH, P2SH-P2WPKH, and single-key-spend P2TR address.
     * @param signerAddress Address of the signing address
     * @param message message_challenge signed by the address 
     * @param signatureBase64 Signature produced by the signing address
     * @returns True if the provided signature is a valid BIP-322 signature for the given message and address, false if otherwise
     * @throws If the provided signature is invalid for the given address, or if unsupported address and signature are provided
     */
    public static verifySignature(signerAddress: string, message: string, signatureBase64: string) {
        // Convert address into corresponding script pubkey
        const scriptPubKey = this.convertAdressToScriptPubkey(signerAddress);
        // Draft corresponding toSpend and toSign transaction using the message and script pubkey
        const toSpendTx = BIP322.buildToSpendTx(message, scriptPubKey);
        const toSignTx = BIP322.buildToSignTx(toSpendTx.getId(), scriptPubKey);
        // Add the witness stack into the toSignTx
        toSignTx.updateInput(0, {
            finalScriptWitness: Buffer.from(signatureBase64, 'base64')
        });
        // Obtain the signature within the witness components
        const witness = toSignTx.extractTransaction().ins[0].witness;
        const encodedSignature = witness[0];
        // Branch depending on whether the signing address is a non-taproot or a taproot address
        if (this.isP2WPKH(witness)) {
            // For non-taproot segwit transaciton, public key is included as the second part of the witness data
            const publicKey = witness[1];
            const { signature } = decodeScriptSignature(encodedSignature);
            // Compute the hash that correspond to the toSignTx
            const hashToSign = this.getHashForSig(toSignTx);
            // Compute OP_HASH160(publicKey)
            const hashedPubkey = bitcoin.crypto.hash160(publicKey);
            // Extract public key hash from scriptPubkey 
            let hashedPubkeyInScriptPubkey: Buffer;
            if (this.isNestedP2WPKH(signerAddress)) {
                // For nested segwit (P2SH-P2WPKH) address, the hashed public key is located from the 3rd byte to the last 2nd byte as OP_HASH160 <HASH> OP_EQUAL
                hashedPubkeyInScriptPubkey = scriptPubKey.subarray(2, -1);
            }
            else {
                // For native segwit address, the hashed public key is located from the 3rd to the end as OP_0 <HASH>
                hashedPubkeyInScriptPubkey = scriptPubKey.subarray(2);
            }
            // Check if OP_HASH160(publicKey) === hashedPubkeyInScriptPubkey
            if (Buffer.compare(hashedPubkey, hashedPubkeyInScriptPubkey) !== 0) {
                throw new Error('Invalid public key listed in witness data.');
            }
            // Computing OP_CHECKSIG in Javascript
            return ecc.verify(hashToSign, publicKey, signature);
        }
        else if (this.isTaprootAddress(signerAddress)) {
            // Check if the witness stack correspond to a single-key-spend P2TR address
            if (!this.isSingleKeyTaproot(witness)) {
                throw new Error('BIP-322 verification from script-spend P2TR is unsupported');
            }
            // For taproot address, the public key is located starting from the 3rd byte of the script public key
            const publicKey = scriptPubKey.subarray(2);
            // Compute the hash to be signed by the signing address
            // Reference: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#user-content-Taproot_key_path_spending_signature_validation
            let hashToSign: Buffer;
            let signature: Buffer;
            if (encodedSignature.byteLength === 64) {
                // If a BIP-341 signature is 64 bytes, the signature is signed using SIGHASH_DEFAULT 0x00 
                hashToSign = this.getTaprootHashForSig(toSignTx, 0x00);
                // And the entirety of the encoded signature is the actual signature
                signature = encodedSignature; 
            }
            else if (encodedSignature.byteLength === 65) {
                // If a BIP-341 signature is 65 bytes, the signature is signed using SIGHASH included at the last byte of the signature
                hashToSign = this.getTaprootHashForSig(toSignTx, encodedSignature[64]);
                // And encodedSignature[0:64] holds the actual signature
                signature = encodedSignature.subarray(0, -1);
            }
            else {
                // Fail validation if the signature is not 64 or 65 bytes
                throw new Error('Incorrect Schnorr signature provided for corresponding Taproot address.');
            }
            // Computing OP_CHECKSIG in Javascript
            return ecc.verifySchnorr(hashToSign, publicKey, signature);
        }
        else {
            throw new Error('Only P2WPKH, P2SH-P2WPKH, and single-key-spend P2TR BIP-322 verification is supported. Unsupported address is provided.');
        }
    }

    /**
     * Check if a given witness stack corresponds to a P2WPKH address.
     * @param witness Witness data associated with the toSign BIP-322 transaction
     * @returns True if the provided address and witness stack correspond to a valid P2WPKH address, false if otherwise
     */
    private static isP2WPKH(witness: Buffer[]) {
        // Check whether the witness stack is as expected for a P2WPKH address
        // It should contain exactly two items, with the second item being a public key with 33 bytes, and the first byte must be either 0x02/0x03
        if (witness.length === 2 && witness[1].byteLength === 33 && (witness[1][0] === 0x02 || witness[1][0] === 0x03)) {
            return true;
        }
        else {
            return false;
        }
    }

    /**
     * Check if a given Bitcoin address is a nested segwit (P2SH-P2WPKH) address.
     * This function assumes the address is either a nested segwit (P2SH-P2WPKH) or native segwit (P2WPKH) address.
     * @param address Bitcoin address to be checked
     * @returns True if the provided address and witness stack correspond to a valid P2SH-P2WPKH address, false if otherwise
     */
    private static isNestedP2WPKH(address: string) {
        // Check if the provided address is a P2SH address
        if (address[0] === '3' || address[0] === '2') {
            return true; // Assume it is a P2SH-P2WPKH address
        }
        else {
            return false; // Assume it is a P2WPKH address
        }
    }

    /**
     * Check if a given Bitcoin address is a taproot address.
     * @param address Bitcoin address to be checked
     * @returns True if the provided address is a taproot address, false if otherwise
     */
    private static isTaprootAddress(address: string) {
        if (address.slice(0, 4) === 'bc1p' || address.slice(0, 4) === 'tb1p') {
            return true; // is taproot address
        }
        else {
            return false;
        }
    }

    /**
     * Check if a given witness stack corresponds to a single-key-spend P2TR address.
     * @param witness Witness data associated with the toSign BIP-322 transaction
     * @returns True if the provided address and witness stack correspond to a valid single-key-spend P2TR address, false if otherwise
     */
    private static isSingleKeyTaproot(witness: Buffer[]) {
        // Check whether the witness stack is as expected for a single-key-spend taproot address
        // It should contain exactly one items which is the signature for the transaction
        if (witness.length === 1) {
            return true;
        }
        else {
            return false;
        }
    }

    /**
     * Convert a given Bitcoin address into its corresponding script public key.
     * Reference: https://github.com/buidl-bitcoin/buidl-python/blob/d79e9808e8ca60975d315be41293cb40d968626d/buidl/script.py#L607
     * @param address Bitcoin address
     * @returns Script public key of the given Bitcoin address
     * @throws Error when the provided address is not a valid Bitcoin address
     */
    private static convertAdressToScriptPubkey(address: string) {
        if (address[0] === '1' || address[0] === 'm' || address[0] === 'n') {
            // P2PKH address
            return bitcoin.payments.p2pkh({
                address: address
            }).output as Buffer;
        }
        else if (address[0] === '3' || address[0] === '2') {
            // P2SH address
            return bitcoin.payments.p2sh({
                address: address
            }).output as Buffer;
        }
        else if (address.slice(0, 4) === 'bc1q' || address.slice(0, 4) === 'tb1q') {
            // P2WPKH or P2WSH address
            if (address.length === 42) {
                // P2WPKH address
                return bitcoin.payments.p2wpkh({
                    address: address
                }).output as Buffer;
            }
            else if (address.length === 62) {
                // P2WSH address
                return bitcoin.payments.p2wsh({
                    address: address
                }).output as Buffer;
            }
        }
        else if (address.slice(0, 4) === 'bc1p' || address.slice(0, 4) === 'tb1p') {
            if (address.length === 62) {
                // P2TR address
                return bitcoin.payments.p2tr({
                    address: address
                }).output as Buffer;
            }
        }
        throw new Error("Unknown address type");
    }

    /**
     * Compute the hash to be signed for a given non-taproot BIP-322 toSign transaction.
     * @param toSignTx PSBT instance of the toSign transaction
     * @returns Computed transaction hash that requires signing
     */
    private static getHashForSig(toSignTx: bitcoin.Psbt) {
        // Create a signing script to unlock the P2WPKH output based on the P2PKH template
        // Reference: https://github.com/bitcoinjs/bitcoinjs-lib/blob/1a9119b53bcea4b83a6aa8b948f0e6370209b1b4/ts_src/psbt.ts#L1654
        const signingScript = bitcoin.payments.p2pkh({ 
            hash: toSignTx.data.inputs[0].witnessUtxo.script.subarray(2) 
        }).output;
        // Return computed transaction hash to be signed 
        return toSignTx.extractTransaction().hashForWitnessV0(
            0,
            signingScript,
            0,
            bitcoin.Transaction.SIGHASH_ALL
        );
    }

    /**
     * Compute the hash to be signed for a given taproot BIP-322 toSign transaction.
     * @param toSignTx PSBT instance of the toSign transaction
     * @param hashType Hash type used to sign the toSign transaction, must be either 0x00 or 0x01
     * @returns Computed transaction hash that requires signing
     * @throws Error if hashType is anything other than 0x00 or 0x01
     */
    private static getTaprootHashForSig(toSignTx: bitcoin.Psbt, hashType: number) {
        // BIP-322 states that 'all signatures must use the SIGHASH_ALL flag'
        // But, in BIP-341, SIGHASH_DEFAULT (0x00) is equivalent to SIGHASH_ALL (0x01) so both should be allowed 
        if (hashType !== bitcoin.Transaction.SIGHASH_DEFAULT && hashType !== bitcoin.Transaction.SIGHASH_ALL) {
            // Throw error if hashType is neither SIGHASH_DEFAULT or SIGHASH_ALL
            throw new Error('Invalid SIGHASH used in signature.');
        }
        // Return computed transaction hash to be signed
        return toSignTx.extractTransaction().hashForWitnessV1(
            0,
            [toSignTx.data.inputs[0].witnessUtxo.script],
            [0],
            hashType
        );
    }

}

export default Verifier;