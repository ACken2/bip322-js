import { Transaction, payments } from "bitcoinjs-lib";
import { PsbtInput } from 'bip174/src/lib/interfaces';

interface PsbtCache {
    __NON_WITNESS_UTXO_TX_CACHE: Transaction[];
    __NON_WITNESS_UTXO_BUF_CACHE: Buffer[];
    __TX_IN_CACHE: { [index: string]: number };
    __TX: Transaction;
    __FEE_RATE?: number;
    __FEE?: number;
    __EXTRACTED_TX?: Transaction;
    __UNSAFE_SIGN_NONSEGWIT: boolean;
}

interface Output {
    script: Buffer;
    value: number;
}

// const isP2MS = isPaymentFactory(payments.p2ms);
// const isP2PK = isPaymentFactory(payments.p2pk);
// const isP2PKH = isPaymentFactory(payments.p2pkh);
const isP2WPKH = isPaymentFactory(payments.p2wpkh);
const isP2WSHScript = isPaymentFactory(payments.p2wsh);
const isP2SHScript = isPaymentFactory(payments.p2sh);
// const isP2TR = isPaymentFactory(payments.p2tr);
const checkRedeemScript = scriptCheckerFactory(payments.p2sh, 'Redeem script');
const checkWitnessScript = scriptCheckerFactory(
    payments.p2wsh,
    'Witness script',
);

// Taken from https://github.com/bitcoinjs/bitcoinjs-lib/blob/5d2ff1c61165932e2814d5f37630e6720168561c/ts_src/psbt.ts#L1591
export function getHashForSig(
    inputIndex: number,
    input: PsbtInput,
    cache: PsbtCache,
    forValidate: boolean,
    sighashTypes?: number[],
): {
    script: Buffer;
    hash: Buffer;
    sighashType: number;
} {
    const unsignedTx = cache.__TX;
    const sighashType = input.sighashType || Transaction.SIGHASH_ALL;
    checkSighashTypeAllowed(sighashType, sighashTypes);

    let hash: Buffer;
    let prevout: Output;

    if (input.nonWitnessUtxo) {
        const nonWitnessUtxoTx = nonWitnessUtxoTxFromCache(
            cache,
            input,
            inputIndex,
        );

        const prevoutHash = unsignedTx.ins[inputIndex].hash;
        const utxoHash = nonWitnessUtxoTx.getHash();

        // If a non-witness UTXO is provided, its hash must match the hash specified in the prevout
        if (!prevoutHash.equals(utxoHash)) {
            throw new Error(
                `Non-witness UTXO hash for input #${inputIndex} doesn't match the hash specified in the prevout`,
            );
        }

        const prevoutIndex = unsignedTx.ins[inputIndex].index;
        prevout = nonWitnessUtxoTx.outs[prevoutIndex] as Output;
    } else if (input.witnessUtxo) {
        prevout = input.witnessUtxo;
    } else {
        throw new Error('Need a Utxo input item for signing');
    }

    const { meaningfulScript, type } = getMeaningfulScript(
        prevout.script,
        inputIndex,
        'input',
        input.redeemScript,
        input.witnessScript,
    );

    if (['p2sh-p2wsh', 'p2wsh'].indexOf(type) >= 0) {
        hash = unsignedTx.hashForWitnessV0(
            inputIndex,
            meaningfulScript,
            prevout.value,
            sighashType,
        );
    } else if (isP2WPKH(meaningfulScript)) {
        // P2WPKH uses the P2PKH template for prevoutScript when signing
        const signingScript = payments.p2pkh({ hash: meaningfulScript.slice(2) })
            .output!;
        hash = unsignedTx.hashForWitnessV0(
            inputIndex,
            signingScript,
            prevout.value,
            sighashType,
        );
    } else {
        // non-segwit
        if (
            input.nonWitnessUtxo === undefined &&
            cache.__UNSAFE_SIGN_NONSEGWIT === false
        )
            throw new Error(
                `Input #${inputIndex} has witnessUtxo but non-segwit script: ` +
                    `${meaningfulScript.toString('hex')}`,
            );
        if (!forValidate && cache.__UNSAFE_SIGN_NONSEGWIT !== false)
            console.warn(
                'Warning: Signing non-segwit inputs without the full parent transaction ' +
                    'means there is a chance that a miner could feed you incorrect information ' +
                    "to trick you into paying large fees. This behavior is the same as Psbt's predecesor " +
                    '(TransactionBuilder - now removed) when signing non-segwit scripts. You are not ' +
                    'able to export this Psbt with toBuffer|toBase64|toHex since it is not ' +
                    'BIP174 compliant.\n*********************\nPROCEED WITH CAUTION!\n' +
                    '*********************',
            );
        hash = unsignedTx.hashForSignature(
            inputIndex,
            meaningfulScript,
            sighashType,
        );
    }

    return {
        script: meaningfulScript,
        sighashType,
        hash,
    };
}

function checkSighashTypeAllowed(
    sighashType: number,
    sighashTypes?: number[],
): void {
    if (sighashTypes && sighashTypes.indexOf(sighashType) < 0) {
        const str = sighashTypeToString(sighashType);
        throw new Error(
            `Sighash type is not allowed. Retry the sign method passing the ` +
                `sighashTypes array of whitelisted types. Sighash type: ${str}`,
        );
    }
}

function sighashTypeToString(sighashType: number): string {
    let text =
        sighashType & Transaction.SIGHASH_ANYONECANPAY
            ? 'SIGHASH_ANYONECANPAY | '
            : '';
    const sigMod = sighashType & 0x1f;
    switch (sigMod) {
        case Transaction.SIGHASH_ALL:
            text += 'SIGHASH_ALL';
            break;
        case Transaction.SIGHASH_SINGLE:
            text += 'SIGHASH_SINGLE';
            break;
        case Transaction.SIGHASH_NONE:
            text += 'SIGHASH_NONE';
            break;
    }
    return text;
}

function nonWitnessUtxoTxFromCache(
    cache: PsbtCache,
    input: PsbtInput,
    inputIndex: number,
): Transaction {
    const c = cache.__NON_WITNESS_UTXO_TX_CACHE;
    if (!c[inputIndex]) {
        addNonWitnessTxCache(cache, input, inputIndex);
    }
    return c[inputIndex];
}

function addNonWitnessTxCache(
    cache: PsbtCache,
    input: PsbtInput,
    inputIndex: number,
): void {
    cache.__NON_WITNESS_UTXO_BUF_CACHE[inputIndex] = input.nonWitnessUtxo!;

    const tx = Transaction.fromBuffer(input.nonWitnessUtxo!);
    cache.__NON_WITNESS_UTXO_TX_CACHE[inputIndex] = tx;

    const self = cache;
    const selfIndex = inputIndex;
    delete input.nonWitnessUtxo;
    Object.defineProperty(input, 'nonWitnessUtxo', {
        enumerable: true,
        get(): Buffer {
            const buf = self.__NON_WITNESS_UTXO_BUF_CACHE[selfIndex];
            const txCache = self.__NON_WITNESS_UTXO_TX_CACHE[selfIndex];
            if (buf !== undefined) {
                return buf;
            } else {
                const newBuf = txCache.toBuffer();
                self.__NON_WITNESS_UTXO_BUF_CACHE[selfIndex] = newBuf;
                return newBuf;
            }
        },
        set(data: Buffer): void {
            self.__NON_WITNESS_UTXO_BUF_CACHE[selfIndex] = data;
        },
    });
}

function getMeaningfulScript(
    script: Buffer,
    index: number,
    ioType: 'input' | 'output',
    redeemScript?: Buffer,
    witnessScript?: Buffer,
): {
    meaningfulScript: Buffer;
    type: 'p2sh' | 'p2wsh' | 'p2sh-p2wsh' | 'raw';
} {
    const isP2SH = isP2SHScript(script);
    const isP2SHP2WSH = isP2SH && redeemScript && isP2WSHScript(redeemScript);
    const isP2WSH = isP2WSHScript(script);

    if (isP2SH && redeemScript === undefined)
        throw new Error('scriptPubkey is P2SH but redeemScript missing');
    if ((isP2WSH || isP2SHP2WSH) && witnessScript === undefined)
        throw new Error(
            'scriptPubkey or redeemScript is P2WSH but witnessScript missing',
        );

    let meaningfulScript: Buffer;

    if (isP2SHP2WSH) {
        meaningfulScript = witnessScript!;
        checkRedeemScript(index, script, redeemScript!, ioType);
        checkWitnessScript(index, redeemScript!, witnessScript!, ioType);
        checkInvalidP2WSH(meaningfulScript);
    } else if (isP2WSH) {
        meaningfulScript = witnessScript!;
        checkWitnessScript(index, script, witnessScript!, ioType);
        checkInvalidP2WSH(meaningfulScript);
    } else if (isP2SH) {
        meaningfulScript = redeemScript!;
        checkRedeemScript(index, script, redeemScript!, ioType);
    } else {
        meaningfulScript = script;
    }
    return {
        meaningfulScript,
        type: isP2SHP2WSH
            ? 'p2sh-p2wsh'
            : isP2SH
            ? 'p2sh'
            : isP2WSH
            ? 'p2wsh'
            : 'raw',
    };
}

function isPaymentFactory(payment: any): (script: Buffer) => boolean {
    return (script: Buffer): boolean => {
        try {
            payment({ output: script });
            return true;
        } catch (err) {
            return false;
        }
    };
}

function scriptCheckerFactory(
    payment: any,
    paymentScriptName: string,
): (idx: number, spk: Buffer, rs: Buffer, ioType: 'input' | 'output') => void {
    return (
        inputIndex: number,
        scriptPubKey: Buffer,
        redeemScript: Buffer,
        ioType: 'input' | 'output',
    ): void => {
        const redeemScriptOutput = payment({
            redeem: { output: redeemScript },
        }).output as Buffer;

        if (!scriptPubKey.equals(redeemScriptOutput)) {
            throw new Error(
                `${paymentScriptName} for ${ioType} #${inputIndex} doesn't match the scriptPubKey in the prevout`,
            );
        }
    };
}

function checkInvalidP2WSH(script: Buffer): void {
    if (isP2WPKH(script) || isP2SHScript(script)) {
        throw new Error('P2WPKH or P2SH can not be contained within P2WSH');
    }
}