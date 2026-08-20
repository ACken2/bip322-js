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

console.log('Verified P2WPKH, testnet, regtest, P2TR, and P2SH-P2WPKH signatures.');
console.log('toSpend txid ' + toSpendTxId);
`;

/**
 * Assert that the installed package declares existing main and types files
 * and does not contain stale dist/src or dist/test output.
 *
 * @param {string} consumerDir Temporary directory that installed the tarball
 */
function assertInstalledPackageLayout(consumerDir) {
    const packageDir = path.join(consumerDir, 'node_modules', 'bip322-js');
    const packageJson = JSON.parse(fs.readFileSync(path.join(packageDir, 'package.json'), 'utf8'));
    if (!packageJson.main) {
        throw new Error('Installed package.json is missing a main field.');
    }
    if (!packageJson.types) {
        throw new Error('Installed package.json is missing a types field.');
    }

    const mainPath = path.resolve(packageDir, packageJson.main);
    const typesPath = path.resolve(packageDir, packageJson.types);
    if (!fs.existsSync(mainPath) || !fs.statSync(mainPath).isFile()) {
        throw new Error(`Installed package main entry does not exist: ${packageJson.main}`);
    }
    if (!fs.existsSync(typesPath) || !fs.statSync(typesPath).isFile()) {
        throw new Error(`Installed package types entry does not exist: ${packageJson.types}`);
    }

    const stalePaths = ['dist/src', 'dist/test']
        .map((relativePath) => path.join(packageDir, relativePath))
        .filter((stalePath) => fs.existsSync(stalePath));
    if (stalePaths.length > 0) {
        const staleList = stalePaths
            .map((stalePath) => path.relative(packageDir, stalePath))
            .join(', ');
        throw new Error(
            `Installed package contains stale output (${staleList}). ` +
            'Remove leftover files under dist/ and rebuild before packing.'
        );
    }

    console.log(`Verified package entries ${packageJson.main} and ${packageJson.types}.`);
}

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
        assertInstalledPackageLayout(consumerDir);
        const consumerPath = path.join(consumerDir, 'readme-example.js');
        fs.writeFileSync(consumerPath, consumerSource);
        const result = run('node', [consumerPath], { cwd: consumerDir });
        if (result.stdout) {
            process.stdout.write(result.stdout);
        }
    }
    finally {
        fs.rmSync(consumerDir, { recursive: true, force: true });
    }
}

let tarballPath;
try {
    console.log('Packing bip322-js...');
    tarballPath = packTarball();
    console.log(`Packed ${path.basename(tarballPath)}`);
    console.log('Installing tarball in a temp directory...');
    runReadmeExample(tarballPath);
    console.log('README example passed.');
}
finally {
    if (tarballPath) {
        fs.rmSync(tarballPath, { force: true });
    }
}
