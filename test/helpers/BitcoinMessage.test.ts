import * as chai from 'chai';
import chaibytes from "chai-bytes";
import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';
import * as ecc from '@bitcoinerlab/secp256k1';
import * as crypto from 'crypto';
import Key from '../../src/helpers/Key';
import VarInt from '../../src/helpers/VarInt';
import BitcoinMessage from '../../src/helpers/BitcoinMessage';
import * as bitcoinMessage from 'bitcoinjs-message'; // Reference implementation

// Setup Chai
chai.use(chaibytes);
const { expect } = chai;

// Initialize ECPair
const ECPair = ECPairFactory(ecc);

describe('BitcoinMessage.sign and BitcoinMessage.verify Compatibility Test Suite', () => {

    // -------------------------------------------------------------------------
    // Setup Test Data
    // -------------------------------------------------------------------------
    const message = "Hello Bitcoin World!";
    const messages = [message, Buffer.from([0x62, 0x75, 0x66, 0x66, 0x65, 0x72])];
    const privateKeyWIF = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1"; // Compressed
    const keyPair = ECPair.fromWIF(privateKeyWIF);
    const privateKey = keyPair.privateKey!;
    const publicKey = keyPair.publicKey;
    
    const keyPairUncompressed = ECPair.fromPrivateKey(privateKey, { compressed: false });
    const publicKeyUncompressed = keyPairUncompressed.publicKey;

    // -------------------------------------------------------------------------
    // Signing & Verification Tests against bitcoinjs-message (Ground Truth)
    // -------------------------------------------------------------------------
    
    const networks = [
        { name: 'Mainnet', network: bitcoin.networks.bitcoin },
        { name: 'Testnet', network: bitcoin.networks.testnet },
        { name: 'Regtest', network: bitcoin.networks.regtest }
    ];

    const scenarios = [
        { type: 'p2pkh', compressed: true, label: 'Legacy (Compressed)' },
        { type: 'p2pkh', compressed: false, label: 'Legacy (Uncompressed)' },
        { type: 'p2sh(p2wpkh)', compressed: true, label: 'Segwit P2SH' },
        { type: 'p2wpkh', compressed: true, label: 'Native Segwit (Bech32)' }
    ];

    networks.forEach(net => {
        scenarios.forEach(scenario => {
            messages.forEach(message => {
                // Skip uncompressed for Segwit types (invalid combination)
                if (!scenario.compressed && scenario.type !== 'p2pkh') return;

                const testName = `[${net.name}] ${scenario.label} ${Buffer.isBuffer(message) ? '(Buffer)' : '(String)'}`;

                it(`should match bitcoinjs-message results: ${testName}`, () => {
                    // 1. Generate Address
                    let payment: bitcoin.Payment;
                    const pubkey = scenario.compressed ? publicKey : publicKeyUncompressed;
                    
                    if (scenario.type === 'p2pkh') {
                        payment = bitcoin.payments.p2pkh({ pubkey, network: net.network });
                    } 
                    else if (scenario.type === 'p2sh(p2wpkh)') {
                        payment = bitcoin.payments.p2sh({ 
                            redeem: bitcoin.payments.p2wpkh({ pubkey, network: net.network }),
                            network: net.network 
                        });
                    } 
                    else { // p2wpkh
                        payment = bitcoin.payments.p2wpkh({ pubkey, network: net.network });
                    }
                    
                    const address = payment.address!;
                    expect(address).to.exist;

                    // 2. Cross-Verification Step

                    // A. Sign using our implementation
                    const sigNew = BitcoinMessage.sign(
                        message, 
                        privateKey, 
                        scenario.compressed, 
                        { segwitType: scenario.type as any }
                    );

                    // B. Sign using REFERENCE implementation (bitcoinjs-message)
                    const sigRef = bitcoinMessage.sign(
                        message, 
                        privateKey, 
                        scenario.compressed, 
                        { segwitType: scenario.type !== 'p2pkh' ? scenario.type as any : undefined }
                    );

                    // Check 1: Byte-for-byte equality (using chai-bytes logic)
                    // Since both use RFC6979 deterministic k, outputs must be identical.
                    expect(sigNew).to.equalBytes(sigRef);

                    // Check 2: Reference library verifies our signature
                    const verifyRef = bitcoinMessage.verify(
                        message, 
                        address, 
                        sigNew.toString('base64')
                    );
                    expect(verifyRef).to.be.true;

                    // Check 3: Use our implementation to verify Reference signature
                    const verifyNew = BitcoinMessage.verify(
                        message, 
                        address, 
                        sigRef.toString('base64')
                    );
                    expect(verifyNew).to.be.true;
                });
            });
        });
    });

    // ---------------------------------------------------------------------
    // Negative Tests
    // ---------------------------------------------------------------------
    it('should fail if the message is tampered', () => {
        const address = bitcoin.payments.p2pkh({ pubkey: publicKey }).address!;
        const signature = BitcoinMessage.sign(message, privateKey, true);
        
        const isValid = BitcoinMessage.verify("Wrong Message", address, signature.toString('base64'));
        expect(isValid).to.be.false;
    });

    // -------------------------------------------------------------------------
    // Setup Test Data for upcoming rejection tests
    // -------------------------------------------------------------------------
    const addressP2PKHUncompressed = bitcoin.payments.p2pkh({ pubkey: publicKeyUncompressed }).address!;
    const addressP2PKHCompressed = bitcoin.payments.p2pkh({ pubkey: publicKey }).address!;
    const addressP2SH = bitcoin.payments.p2sh({ 
        redeem: bitcoin.payments.p2wpkh({ pubkey: publicKey })
    }).address!;
    const addressP2WPKH = bitcoin.payments.p2wpkh({ pubkey: publicKey }).address!;
    const addressP2TR = bitcoin.payments.p2tr({ pubkey: Key.toXOnly(publicKey) }).address!;

    const addressLists = [addressP2PKHUncompressed, addressP2PKHCompressed, addressP2SH, addressP2WPKH, addressP2TR];
    const testSuite = [
        { address: addressP2PKHUncompressed, compressed: false, options: undefined, name: 'P2PKH Uncompressed' },
        { address: addressP2PKHCompressed, compressed: true, options: undefined, name: 'P2PKH Compressed' },
        { address: addressP2SH, compressed: true, options: { segwitType: 'p2sh(p2wpkh)' }, name: 'P2SH-P2WPKH' },
        { address: addressP2WPKH, compressed: true, options: { segwitType: 'p2wpkh' }, name: 'P2WPKH' }
    ];

    // -------------------------------------------------------------------------
    // Testing whether signature generated for one address type would get rejected for all other address types
    // -------------------------------------------------------------------------
    testSuite.forEach(testCase => {
        it(`${testCase.name} signature should be rejected for mismatched address`, () => {
            const signature = BitcoinMessage.sign(message, privateKey, testCase.compressed, (testCase.options as any));
            addressLists.forEach(address => {
                const isValid = BitcoinMessage.verify(message, address, signature.toString('base64'));
                expect(isValid).to.equal(address === testCase.address); // Signature is valid if address equals to the test case address
            })
        });
    });

    it('should fail if signature is not 65 bytes', () => {
        const address = bitcoin.payments.p2pkh({ pubkey: publicKey }).address!;
        let signature = BitcoinMessage.sign(message, privateKey, true);
        
        // Remove one byte
        const signatureTooShort = signature.subarray(1);
        // Add one byte at the end
        const signatureTooLong = Buffer.concat([signature, Buffer.from([0x01])]);

        const isValidTooShort = BitcoinMessage.verify(message, address, signatureTooShort.toString('base64'));
        expect(isValidTooShort).to.be.false;
        const isValidTooLong = BitcoinMessage.verify(message, address, signatureTooLong.toString('base64'));
        expect(isValidTooLong).to.be.false;
    });

    it('should fail if signature is corrupted', () => {
        const address = bitcoin.payments.p2pkh({ pubkey: publicKey }).address!;
        let signature = BitcoinMessage.sign(message, privateKey, true);
        
        // Corrupt one byte
        signature[10] = signature[10] ^ 0xFF; 

        const isValid = BitcoinMessage.verify(message, address, signature.toString('base64'));
        expect(isValid).to.be.false;
    });

    it('should fail if address is invalid', () => {
        const address = bitcoin.payments.p2pkh({ pubkey: publicKey }).address!;
        let signature = BitcoinMessage.sign(message, privateKey, true);
        
        const isValid = BitcoinMessage.verify(message, `${address}1`, signature.toString('base64'));
        expect(isValid).to.be.false;
    });

    it('should fail if header is invalid (recId > 3)', () => {
        const address = bitcoin.payments.p2wpkh({ pubkey: publicKey }).address!;
        let signature = BitcoinMessage.sign(message, privateKey, true, { segwitType: 'p2wpkh' });

        // Add 4 to the header bit
        // This would make it invalid in BIP-137 standard (header = 44; recId = 5)
        signature[0] += 4;
        const isValid = BitcoinMessage.verify(message, address, signature.toString('base64'));
        expect(isValid).to.be.false;
    });

    it('should fail if header is invalid (recId < 0)', () => {
        const address = bitcoin.payments.p2pkh({ pubkey: publicKeyUncompressed }).address!;
        let signature = BitcoinMessage.sign(message, privateKey, false);

        // Subtract 4 to the header bit
        // This would make it invalid in BIP-137 standard (header = 24; recId = -3)
        signature[0] -= 4;
        const isValid = BitcoinMessage.verify(message, address, signature.toString('base64'));
        expect(isValid).to.be.false;
    });

    it('should fail if message is neither string or buffer', () => {
        const address = bitcoin.payments.p2pkh({ pubkey: publicKey }).address!;
        let signature = BitcoinMessage.sign(message, privateKey, true);
        
        const isValid = BitcoinMessage.verify(({ whoami: 'def only a string/buffer' } as any), address, signature.toString('base64'));
        expect(isValid).to.be.false;
    });
    
    it('should properly handle Testnet addresses without explicit network param', () => {
        const net = bitcoin.networks.testnet;
        const payment = bitcoin.payments.p2pkh({ pubkey: publicKey, network: net });
        const address = payment.address!; 
        
        const signature = BitcoinMessage.sign(message, privateKey, true);
        
        // Auto-detect network in verify()
        const isValid = BitcoinMessage.verify(message, address, signature.toString('base64'));
        expect(isValid).to.be.true;
    });

    it('should properly handle Regtest addresses without explicit network param', () => {
        const net = bitcoin.networks.regtest;
        const payment = bitcoin.payments.p2pkh({ pubkey: publicKey, network: net });
        const address = payment.address!; 
        
        const signature = BitcoinMessage.sign(message, privateKey, true);
        
        // Auto-detect network in verify()
        const isValid = BitcoinMessage.verify(message, address, signature.toString('base64'));
        expect(isValid).to.be.true;
    });

});

describe('BitcoinMessage.magicHash', () => {
    
    /**
     * Helper to manually calculate the expected Magic Hash using Node's crypto.
     * This acts as the independent "ground truth" to verify the implementation.
     */
    function calculateExpectedHash(message: Buffer | string): Buffer {
        const prefix = Buffer.from('\x18Bitcoin Signed Message:\n', 'utf8');
        const messageBuf = Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf8');
        
        // 1. Encode Length
        const len = VarInt.encode(messageBuf.length);
        
        // 2. Concatenate: Prefix + Length + Message
        const payload = Buffer.concat([prefix, len, messageBuf]);
        
        // 3. Double SHA-256
        const hash1 = crypto.createHash('sha256').update(payload).digest();
        const hash2 = crypto.createHash('sha256').update(hash1).digest();
        
        return hash2;
    }

    it('should correctly hash a standard ASCII string', () => {
        const message = "Hello Bitcoin";
        const expected = calculateExpectedHash(message);
        const actual = BitcoinMessage.magicHash(message);

        expect(actual).to.equalBytes(expected);
    });

    it('should correctly hash a Buffer input', () => {
        const message = Buffer.from("Buffer Message", 'utf8');
        const expected = calculateExpectedHash(message);
        const actual = BitcoinMessage.magicHash(message);

        expect(actual).to.equalBytes(expected);
    });

    it('should correctly hash an empty string', () => {
        const message = "";
        const expected = calculateExpectedHash(message);
        const actual = BitcoinMessage.magicHash(message);

        expect(actual).to.equalBytes(expected);
    });

    it('should correctly hash a UTF-8 string with special characters', () => {
        const message = "₿itcoin: The Future! 🚀";
        const expected = calculateExpectedHash(message);
        const actual = BitcoinMessage.magicHash(message);

        expect(actual).to.equalBytes(expected);
    });

    it('should match a known test vector (Hardcoded check)', () => {
        // Known vector for message "hello"
        // Prefix: 18426974636f696e205369676e6564204d6573736167653a0a (25 bytes)
        // Len: 05 (1 byte)
        // Msg: 68656c6c6f (5 bytes)
        // SHA256(SHA256(18...0a0568656c6c6f))
        const message = "hello";
        
        // Calculated via: echo -n -e "\x18Bitcoin Signed Message:\n\x05hello" | openssl dgst -sha256 -binary | openssl dgst -sha256
        // Result: cf0447ec85f0ce7150a257db32ebfcb7523dae17c36dbd1be598779fec0484f4
        const expectedHex = "cf0447ec85f0ce7150a257db32ebfcb7523dae17c36dbd1be598779fec0484f4";
        
        const actual = BitcoinMessage.magicHash(message);
        
        expect(actual.toString('hex')).to.equal(expectedHex);
    });

});