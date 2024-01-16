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
     * Check if a given Bitcoin address is a pay-to-witness-public-key-hash (P2WPKH) address.
     * @param address Bitcoin address to be checked
     * @returns True if the provided address correspond to a valid P2WPKH address, false if otherwise
     */
    public static isP2WPKH(address: string) {
        // Check if the provided address is a P2WPKH/P2WSH address
        if (/^(bc1q|tb1q|bcrt1q)/.test(address)) {
            // Either a P2WPKH / P2WSH address
            // Convert the address into a scriptPubKey
            const scriptPubKey = this.convertAdressToScriptPubkey(address);
            // Check if the scriptPubKey is exactly 22 bytes since P2WPKH scriptPubKey should be 0014<20-BYTE-PUBKEY-HASH>
            if (scriptPubKey.byteLength === 22) {
                return true; // P2WPKH
            }
            else {
                return false; // Not P2WPKH, probably P2WSH
            }
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
        if (/^(bc1p|tb1p|bcrt1p)/.test(address)) {
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
    public static isP2WPKHWitness(witness: Buffer[]) {
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
    public static isSingleKeyP2TRWitness(witness: Buffer[]) {
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
     * Determine network type by checking addresses prefixes
     * Reference: https://en.bitcoin.it/wiki/List_of_address_prefixes
     * @param address Bitcoin address
     * @returns Network type
     */
    public static getNetworkFromAddess(address: string) {
        if (/^(bc1q|bc1p|1|3)/.test(address)) return bitcoin.networks.bitcoin
        if (/^(tb1q|tb1p|2|m|n)/.test(address)) return bitcoin.networks.testnet
        if (/^(bcrt1q|bcrt1p)/.test(address)) return bitcoin.networks.regtest

        return bitcoin.networks.bitcoin
    }

    /**
     * Convert a given Bitcoin address into its corresponding script public key.
     * Reference: https://github.com/buidl-bitcoin/buidl-python/blob/d79e9808e8ca60975d315be41293cb40d968626d/buidl/script.py#L607
     * @param address Bitcoin address
     * @returns Script public key of the given Bitcoin address
     * @throws Error when the provided address is not a valid Bitcoin address
     */
    public static convertAdressToScriptPubkey(address: string) {
        if (address.startsWith('1') || address.startsWith('m') || address.startsWith('n')) {
            // P2PKH address
            return bitcoin.payments.p2pkh({
                address: address,
                network: this.getNetworkFromAddess(address)
            }).output;
        }
        else if (address.startsWith('3') || address.startsWith('2')) {
            // P2SH address
            return bitcoin.payments.p2sh({
                address: address,
                network: this.getNetworkFromAddess(address)
            }).output;
        }
        else if (/^(bc1q|tb1q|bcrt1q)/.test(address)) {
            // P2WPKH or P2WSH address
            if (address.length === 42 || (address.includes('bcrt1q') && address.length === 44)) {
                // P2WPKH address
                return bitcoin.payments.p2wpkh({
                    address: address,
                    network: this.getNetworkFromAddess(address)
                }).output;
            }
            else if (address.length === 62 || (address.includes('bcrt1q') && address.length === 64)) {
                // P2WSH address
                return bitcoin.payments.p2wsh({
                    address: address,
                    network: this.getNetworkFromAddess(address)
                }).output;
            }
        }
        else if (/^(bc1p|tb1p|bcrt1p)/.test(address)) {
            if (address.length === 62) {
                // P2TR address
                return bitcoin.payments.p2tr({
                    address: address,
                    network: this.getNetworkFromAddess(address)
                }).output;
            }
        }
        throw new Error("Unknown address type");
    }

    /**
     * Convert a given public key into a corresponding Bitcoin address.
     * @param publicKey Public key for deriving the address, or internal public key for deriving taproot address
     * @param addressType Bitcoin address type to be derived, must be either 'p2pkh', 'p2sh-p2wpkh', 'p2wpkh', or 'p2tr'
     * @returns Bitcoin address that correspond to the given public key in both mainnet and testnet
     */
    public static convertPubKeyIntoAddress(publicKey: Buffer, addressType: 'p2pkh' | 'p2sh-p2wpkh' | 'p2wpkh' | 'p2tr', network: bitcoin.Network = bitcoin.networks.bitcoin) {
        switch (addressType) {
            case 'p2pkh':
                return bitcoin.payments.p2pkh({ pubkey: publicKey, network }).address
            case 'p2sh-p2wpkh':
                // Reference: https://github.com/bitcoinjs/bitcoinjs-lib/blob/1a9119b53bcea4b83a6aa8b948f0e6370209b1b4/test/integration/addresses.spec.ts#L70
                return bitcoin.payments.p2sh({ 
                        redeem: bitcoin.payments.p2wpkh({ pubkey: publicKey, network }), 
                        network 
                    }).address
            case 'p2wpkh':
                return bitcoin.payments.p2wpkh({ pubkey: publicKey, network }).address
            case 'p2tr':
                // Convert full-length public key into internal public key if necessary
                const internalPubkey = publicKey.byteLength === 33 ? publicKey.subarray(1, 33) : publicKey;
                return bitcoin.payments.p2tr({ internalPubkey: internalPubkey, network }).address
            default:
                throw new Error('Cannot convert public key into unsupported address type.');
        }
    }

}

export default Address;