// Import modules to be exported
import BIP322 from "./BIP322";
import Signer from "./Signer";
import Verifier from "./Verifier";
import { Address, BIP137, Key, Witness } from "./helpers";

// Provide a ECC library to bitcoinjs-lib
import ecc from '@bitcoinerlab/secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
bitcoin.initEccLib(ecc);

// Export
export { BIP322, Signer, Verifier, Address, BIP137, Key, Witness };