'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..');

/**
 * Run a command and throw if it exits with a non-zero status.
 *
 * @param {string} command Command to execute
 * @param {string[]} args Command arguments
 * @param {import('child_process').SpawnSyncOptionsWithStringEncoding} [options] Spawn options
 * @returns {import('child_process').SpawnSyncReturns<string>} Command result
 */
function run(command, args, options = {}) {
    const result = spawnSync(command, args, {
        encoding: 'utf8',
        ...options
    });
    if (result.status !== 0) {
        const output = `${result.stdout || ''}${result.stderr || ''}`;
        throw new Error(`${command} ${args.join(' ')} failed:\n${output}`);
    }
    return result;
}

/**
 * Pack the package and return the absolute path of the generated tarball.
 *
 * @returns {string} Absolute path to the packed tarball
 */
function packTarball() {
    const result = run('npm', ['pack', '--json'], { cwd: repoRoot });
    const packed = JSON.parse(result.stdout);
    const filename = Array.isArray(packed) ? packed[0].filename : packed.filename;
    return path.join(repoRoot, filename);
}

const consumerSource = `'use strict';

const { BIP322, Signer, Verifier } = require('bip322-js');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

const privateKey = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
const address = 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l';
const addressTestnet = 'tb1q9vza2e8x573nczrlzms0wvx3gsqjx7vaxwd45v';
const addressRegtest = 'bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vay85cr9';
const taprootAddress = 'bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3';
const nestedSegwitAddress = '37qyp7jQAzqb2rCBpMvVtLDuuzKAUCVnJb';
const message = 'Hello World';

const signature = Signer.sign(privateKey, address, message);
const signatureTestnet = Signer.sign(privateKey, addressTestnet, message);
const signatureRegtest = Signer.sign(privateKey, addressRegtest, message);
const signatureP2TR = Signer.sign(privateKey, taprootAddress, message);
const signatureP2SH = Signer.sign(privateKey, nestedSegwitAddress, message);

assert(Verifier.verifySignature(address, message, signature), 'P2WPKH verification failed');
assert(Verifier.verifySignature(addressTestnet, message, signatureTestnet), 'Testnet P2WPKH verification failed');
assert(Verifier.verifySignature(addressRegtest, message, signatureRegtest), 'Regtest P2WPKH verification failed');
assert(Verifier.verifySignature(taprootAddress, message, signatureP2TR), 'P2TR verification failed');
assert(Verifier.verifySignature(nestedSegwitAddress, message, signatureP2SH), 'P2SH-P2WPKH verification failed');

const scriptPubKey = Buffer.from('00142b05d564e6a7a33c087f16e0f730d1440123799d', 'hex');
const toSpend = BIP322.buildToSpendTx(message, scriptPubKey);
const toSpendTxId = toSpend.getId();
assert(/^[0-9a-f]{64}$/.test(toSpendTxId), 'toSpend.getId() did not return a 64-character hex string');
const toSign = BIP322.buildToSignTx(toSpendTxId, scriptPubKey);
assert(toSign, 'BIP322.buildToSignTx did not return a PSBT');
`;

/**
 * Install the packed tarball in a temp directory and run the README example.
 *
 * @param {string} tarballPath Absolute path to the packed tarball
 */
function runReadmeExample(tarballPath) {
    const consumerDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bip322-js-smoke-'));
    try {
        run('npm', ['init', '-y'], { cwd: consumerDir });
        run('npm', ['install', tarballPath], { cwd: consumerDir });
        const consumerPath = path.join(consumerDir, 'readme-example.js');
        fs.writeFileSync(consumerPath, consumerSource);
        run('node', [consumerPath], { cwd: consumerDir });
    }
    finally {
        fs.rmSync(consumerDir, { recursive: true, force: true });
    }
}

let tarballPath;
try {
    tarballPath = packTarball();
    runReadmeExample(tarballPath);
}
finally {
    if (tarballPath) {
        fs.rmSync(tarballPath, { force: true });
    }
}
