// Import dependency
import * as bitcoin from 'bitcoinjs-lib';

/**
 * Class that implement address-related utility functions.
 */
class Address {

    /**
     * Check if a given Bitcoin address is a pay-to-public-key-hash (p2pkh) address.
     * @param address Bitcoin address to be checked
     * @returns True if the provided address correspond to a valid P2PKH address, false if otherwise
     */
    public static isP2PKH(address: string) {
        // Check if the provided address is a P2PKH address
        if (address[0] === '1' || address[0] === 'm' || address[0] === 'n') {
            return true; // P2PKH address
        }
        else {
            return false;
        }
    }

    /**
     * Check if a given Bitcoin address is a pay-to-script-hash (P2SH) address.
     * @param address Bitcoin address to be checked
     * @returns True if the provided address correspond to a valid P2SH address, false if otherwise
     */
    public static isP2SH(address: string) {
        // Check if the provided address is a P2SH address
        if (address[0] === '3' || address[0] === '2') {
            return true; // P2SH address
        }
        else {
            return false;
        }
    }

    /**
     * Check if a given Bitcoin address is a taproot address.
     * @param address Bitcoin address to be checked
     * @returns True if the provided address is a taproot address, false if otherwise
     */
    public static isP2TR(address: string) {
        if (address.slice(0, 4) === 'bc1p' || address.slice(0, 4) === 'tb1p') {
            return true; // P2TR address
        }
        else {
            return false;
        }
    }

    /**
     * Check if a given witness stack corresponds to a P2WPKH address.
     * @param witness Witness data associated with the toSign BIP-322 transaction
     * @returns True if the provided witness stack correspond to a valid P2WPKH address, false if otherwise
     */
    public static isP2WPKH(witness: Buffer[]) {
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
     * Check if a given witness stack corresponds to a single-key-spend P2TR address.
     * @param witness Witness data associated with the toSign BIP-322 transaction
     * @returns True if the provided address and witness stack correspond to a valid single-key-spend P2TR address, false if otherwise
     */
    public static isSingleKeyP2TR(witness: Buffer[]) {
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
    public static convertAdressToScriptPubkey(address: string) {
        if (address[0] === '1' || address[0] === 'm' || address[0] === 'n') {
            // P2PKH address
            return bitcoin.payments.p2pkh({
                address: address,
                network: (address[0] === '1') ? bitcoin.networks.bitcoin : bitcoin.networks.testnet
            }).output as Buffer;
        }
        else if (address[0] === '3' || address[0] === '2') {
            // P2SH address
            return bitcoin.payments.p2sh({
                address: address,
                network: (address[0] === '3') ? bitcoin.networks.bitcoin : bitcoin.networks.testnet
            }).output as Buffer;
        }
        else if (address.slice(0, 4) === 'bc1q' || address.slice(0, 4) === 'tb1q') {
            // P2WPKH or P2WSH address
            if (address.length === 42) {
                // P2WPKH address
                return bitcoin.payments.p2wpkh({
                    address: address,
                    network: (address.slice(0, 4) === 'bc1q') ? bitcoin.networks.bitcoin : bitcoin.networks.testnet
                }).output as Buffer;
            }
            else if (address.length === 62) {
                // P2WSH address
                return bitcoin.payments.p2wsh({
                    address: address,
                    network: (address.slice(0, 4) === 'bc1q') ? bitcoin.networks.bitcoin : bitcoin.networks.testnet
                }).output as Buffer;
            }
        }
        else if (address.slice(0, 4) === 'bc1p' || address.slice(0, 4) === 'tb1p') {
            if (address.length === 62) {
                // P2TR address
                return bitcoin.payments.p2tr({
                    address: address,
                    network: (address.slice(0, 4) === 'bc1p') ? bitcoin.networks.bitcoin : bitcoin.networks.testnet
                }).output as Buffer;
            }
        }
        throw new Error("Unknown address type");
    }

}

export default Address;