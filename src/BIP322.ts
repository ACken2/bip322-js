// Import dependencies
import { VarInt, VarStr } from "./helpers";
import { Hash } from "fast-sha256";
import * as bitcoin from 'bitcoinjs-lib';
import ecc from '@bitcoinerlab/secp256k1';

/**
 * Class that handles BIP-322 related operations.
 * Reference: https://github.com/LegReq/bip0322-signatures/blob/master/BIP0322_signing.ipynb
 */
class BIP322 {

    // BIP322 message tag
    static TAG = Buffer.from("BIP0322-signed-message");

    /**
     * Compute the message hash as specified in the BIP-322.
     * The standard is specified in BIP-340 as:
     *      The function hashtag(x) where tag is a UTF-8 encoded tag name and x is a byte array returns the 32-byte hash SHA256(SHA256(tag) || SHA256(tag) || x).
     * @param message Message to be hashed
     * @returns Hashed message
     */
    public static hashMessage(message: string) {
        // Compute the message hash - SHA256(SHA256(tag) || SHA256(tag) || message)
        const tagHasher = new Hash();
        tagHasher.update(this.TAG);
        const tagHash = tagHasher.digest();
        const messageHasher = new Hash();
        messageHasher.update(tagHash);
        messageHasher.update(tagHash);
        messageHasher.update(Buffer.from(message));
        const messageHash = messageHasher.digest();
        return messageHash;
    }

    /**
     * Build a to_spend transaction using simple signature in accordance to the BIP-322.
     * @param message Message to be signed using BIP-322
     * @param scriptPublicKey The script public key for the signing wallet
     * @returns Bitcoin transaction that correspond to the to_spend transaction
     */
    public static buildToSpendTx(message: string, scriptPublicKey: Buffer) {
        // Initialize Bitcoin lib
        bitcoin.initEccLib(ecc);
        // Create PSBT object for constructing the transaction
        const psbt = new bitcoin.Psbt();
        // Set default value for nVersion and nLockTime
        psbt.setVersion(0); // nVersion = 0
        psbt.setLocktime(0); // nLockTime = 0
        // Compute the message hash - SHA256(SHA256(tag) || SHA256(tag) || message)
        const messageHash = this.hashMessage(message);
        // Construct the scriptSig - OP_0 PUSH32[ message_hash ]
        const scriptSigPartOne = new Uint8Array([0x00, 0x20]); // OP_0 PUSH32
        const scriptSig = new Uint8Array(scriptSigPartOne.length + messageHash.length);
        scriptSig.set(scriptSigPartOne);
        scriptSig.set(messageHash, scriptSigPartOne.length);
        // Set the input
        psbt.addInput({
            hash: '0'.repeat(64), // vin[0].prevout.hash = 0000...000
            index: 0xFFFFFFFF, // vin[0].prevout.n = 0xFFFFFFFF
            sequence: 0, // vin[0].nSequence = 0
            finalScriptSig: Buffer.from(scriptSig), // vin[0].scriptSig = OP_0 PUSH32[ message_hash ]
            witnessScript: Buffer.from([]) // vin[0].scriptWitness = []
        });
        // Set the output
        psbt.addOutput({
            value: 0, // vout[0].nValue = 0
            script: scriptPublicKey // vout[0].scriptPubKey = message_challenge
        });
        // Return transaction
        return psbt.extractTransaction();
    }

    /**
     * Build a to_sign transaction using simple signature in accordance to the BIP-322.
     * @param toSpendTxId Transaction ID of the to_spend transaction as constructed by buildToSpendTx
     * @param witnessScript The script public key for the signing wallet, or the redeemScript for P2SH-P2WPKH address
     * @param isRedeemScript Set to true if the provided witnessScript is a redeemScript for P2SH-P2WPKH address, default to false
     * @returns Ready-to-be-signed bitcoinjs.Psbt transaction
     */
    public static buildToSignTx(toSpendTxId: string, witnessScript: Buffer, isRedeemScript: boolean = false) {
        // Initialize Bitcoin lib
        bitcoin.initEccLib(ecc);
        // Create PSBT object for constructing the transaction
        const psbt = new bitcoin.Psbt();
        // Set default value for nVersion and nLockTime
        psbt.setVersion(0); // nVersion = 0
        psbt.setLocktime(0); // nLockTime = 0
        // Set the input
        psbt.addInput({
            hash: toSpendTxId, // vin[0].prevout.hash = to_spend.txid
            index: 0, // vin[0].prevout.n = 0
            sequence: 0, // vin[0].nSequence = 0
            witnessUtxo: {
                script: witnessScript,
                value: 0
            }
        });
        // Set redeemScript as witnessScript if isRedeemScript
        if (isRedeemScript) {
            psbt.updateInput(0, {
                redeemScript: witnessScript
            });
        }
        // Set the output
        psbt.addOutput({
            value: 0, // vout[0].nValue = 0
            script: Buffer.from([0x6a]) // vout[0].scriptPubKey = OP_RETURN
        });
        return psbt;
    }

    /**
     * Encode array of witness into its base-64 encoded format.
     * Follows the encoding scheme found in buidl-python:
     *      https://github.com/buidl-bitcoin/buidl-python/blob/d79e9808e8ca60975d315be41293cb40d968626d/buidl/witness.py#L35
     *      https://github.com/buidl-bitcoin/buidl-python/blob/d79e9808e8ca60975d315be41293cb40d968626d/buidl/helper.py#L203
     *      https://github.com/buidl-bitcoin/buidl-python/blob/d79e9808e8ca60975d315be41293cb40d968626d/buidl/helper.py#L180
     * @param witnesses Array of witness data
     * @returns Base-64 encoded witness data
     */
    public static encodeWitness(witnesses: Uint8Array[]) {
        // Store the current witness stack
        // The first element to be included is the length of the witness array as VarInt
        let witnessStack = VarInt.encode(witnesses.length);
        // Then, for each witness array,
        witnesses.forEach((witness) => {
            // Append the length of the witness, and then its entire content to the witness stack
            witnessStack = Buffer.concat([ witnessStack, VarStr.encode(Buffer.from(witness)) ]);
        });
        // Return the base-64 encoded witness stack
        return witnessStack.toString('base64');
    }

}

export default BIP322;