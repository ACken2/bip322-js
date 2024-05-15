// Import dependencies
import { expect, use } from 'chai';
import chaibytes from "chai-bytes";
import ECPairFactory from 'ecpair';
import * as bitcoin from 'bitcoinjs-lib';
import ecc from '@bitcoinerlab/secp256k1';

// Import module to be tested
import { Address } from '../../src';

describe('Address Test', () => {

    before(() => {
        use(chaibytes);
    });

    describe('Address Recognition Functions', () => {

        // Arrange
        // P2PKH
        const p2pkhMainnet = '17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem';
        const p2pkhTestnet = 'mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn';
        const p2pkhTestnetII = 'n11112Lo13n4GvQhQpDtLY8KH7KNeCVmvw';
        const p2pkhRegtest = 'mjSSLdHFzft9NC5NNMik7WrMQ9rRhMhNpT';
        // P2SH
        const p2shMainnet = '3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX';
        const p2shTestnet = '2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc';
        const p2shRegtest = '2MyQBsrfRnTLwEdpjVVYNWHDB8LXLJUcub9';
        // P2WPKH
        const p2wpkhMainnet = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
        const p2wpkhTestnet = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
        const p2wpkhRegtest = 'bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vay85cr9';
        // P2WSH
        const p2wshMainnet = 'bc1qeklep85ntjz4605drds6aww9u0qr46qzrv5xswd35uhjuj8ahfcqgf6hak';
        const p2wshTestnet = 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7';
        const p2wshRegtest = 'bcrt1qruu5mtcgx8fpz58uquwjke6tte88uykrr06nhgu9eruv2j370lesyhj9au';
        // P2TR
        const p2trMainnet = 'bc1p000022222333333444444455555555666666666999999999zz9qzagays';
        const p2trTestnet = 'tb1p000273lqsqqfw2a6h2vqxr2tll4wgtv7zu8a30rz4mhree8q5jzq8cjtyp';
        const p2trRegtest = 'bcrt1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5su3mkyy';

        it('Classify if a given address is a P2PKH address correctly', () => {
            // Act
            const p2pkhMainnetResult = Address.isP2PKH(p2pkhMainnet);
            const p2pkhTestnetResult = Address.isP2PKH(p2pkhTestnet);
            const p2pkhTestnetIIResult = Address.isP2PKH(p2pkhTestnetII);
            const p2pkhRegtestResult = Address.isP2PKH(p2pkhRegtest);
            const p2shMainnetResult = Address.isP2PKH(p2shMainnet);
            const p2shTestnetResult = Address.isP2PKH(p2shTestnet);
            const p2shRegtestResult = Address.isP2PKH(p2shRegtest);
            const p2wpkhMainnetResult = Address.isP2PKH(p2wpkhMainnet);
            const p2wpkhTestnetResult = Address.isP2PKH(p2wpkhTestnet);
            const p2wpkhRegtestResult = Address.isP2PKH(p2wpkhRegtest);
            const p2wshMainnetResult = Address.isP2PKH(p2wshMainnet);
            const p2wshTestnetResult = Address.isP2PKH(p2wshTestnet);
            const p2wshRegtestResult = Address.isP2PKH(p2wshRegtest);
            const p2trMainnetResult = Address.isP2PKH(p2trMainnet);
            const p2trTestnetResult = Address.isP2PKH(p2trTestnet);
            const p2trRegtestResult = Address.isP2PKH(p2trRegtest);

            // Assert
            expect(p2pkhMainnetResult).to.be.true;
            expect(p2pkhTestnetResult).to.be.true;
            expect(p2pkhTestnetIIResult).to.be.true;
            expect(p2pkhRegtestResult).to.be.true;
            expect(p2shMainnetResult).to.be.false;
            expect(p2shTestnetResult).to.be.false;
            expect(p2shRegtestResult).to.be.false;
            expect(p2wpkhMainnetResult).to.be.false;
            expect(p2wpkhTestnetResult).to.be.false;
            expect(p2wpkhRegtestResult).to.be.false;
            expect(p2wshMainnetResult).to.be.false;
            expect(p2wshTestnetResult).to.be.false;
            expect(p2wshRegtestResult).to.be.false;
            expect(p2trMainnetResult).to.be.false;
            expect(p2trTestnetResult).to.be.false;
            expect(p2trRegtestResult).to.be.false;
        });

        it('Classify if a given address is a P2SH address correctly', () => {
            // Act
            const p2pkhMainnetResult = Address.isP2SH(p2pkhMainnet);
            const p2pkhTestnetResult = Address.isP2SH(p2pkhTestnet);
            const p2pkhTestnetIIResult = Address.isP2SH(p2pkhTestnetII);
            const p2pkhRegtestResult = Address.isP2SH(p2pkhRegtest);
            const p2shMainnetResult = Address.isP2SH(p2shMainnet);
            const p2shTestnetResult = Address.isP2SH(p2shTestnet);
            const p2shRegtestResult = Address.isP2SH(p2shRegtest);
            const p2wpkhMainnetResult = Address.isP2SH(p2wpkhMainnet);
            const p2wpkhTestnetResult = Address.isP2SH(p2wpkhTestnet);
            const p2wpkhRegtestResult = Address.isP2SH(p2wpkhRegtest);
            const p2wshMainnetResult = Address.isP2SH(p2wshMainnet);
            const p2wshTestnetResult = Address.isP2SH(p2wshTestnet);
            const p2wshRegtestResult = Address.isP2SH(p2wshRegtest);
            const p2trMainnetResult = Address.isP2SH(p2trMainnet);
            const p2trTestnetResult = Address.isP2SH(p2trTestnet);
            const p2trRegtestResult = Address.isP2SH(p2trRegtest);

            // Assert
            expect(p2pkhMainnetResult).to.be.false;
            expect(p2pkhTestnetResult).to.be.false;
            expect(p2pkhTestnetIIResult).to.be.false;
            expect(p2pkhRegtestResult).to.be.false;
            expect(p2shMainnetResult).to.be.true;
            expect(p2shTestnetResult).to.be.true;
            expect(p2shRegtestResult).to.be.true;
            expect(p2wpkhMainnetResult).to.be.false;
            expect(p2wpkhTestnetResult).to.be.false;
            expect(p2wpkhRegtestResult).to.be.false;
            expect(p2wshMainnetResult).to.be.false;
            expect(p2wshTestnetResult).to.be.false;
            expect(p2wshRegtestResult).to.be.false;
            expect(p2trMainnetResult).to.be.false;
            expect(p2trTestnetResult).to.be.false;
            expect(p2trRegtestResult).to.be.false;
        });

        it('Classify if a given address is a P2WPKH address correctly', () => {
            // Act
            const p2pkhMainnetResult = Address.isP2WPKH(p2pkhMainnet);
            const p2pkhTestnetResult = Address.isP2WPKH(p2pkhTestnet);
            const p2pkhTestnetIIResult = Address.isP2WPKH(p2pkhTestnetII);
            const p2pkhRegtestResult = Address.isP2WPKH(p2pkhRegtest);
            const p2shMainnetResult = Address.isP2WPKH(p2shMainnet);
            const p2shTestnetResult = Address.isP2WPKH(p2shTestnet);
            const p2shRegtestResult = Address.isP2WPKH(p2shRegtest);
            const p2wpkhMainnetResult = Address.isP2WPKH(p2wpkhMainnet);
            const p2wpkhTestnetResult = Address.isP2WPKH(p2wpkhTestnet);
            const p2wpkhRegtestResult = Address.isP2WPKH(p2wpkhRegtest);
            const p2wshMainnetResult = Address.isP2WPKH(p2wshMainnet);
            const p2wshTestnetResult = Address.isP2WPKH(p2wshTestnet);
            const p2wshRegtestResult = Address.isP2WPKH(p2wshRegtest);
            const p2trMainnetResult = Address.isP2WPKH(p2trMainnet);
            const p2trTestnetResult = Address.isP2WPKH(p2trTestnet);
            const p2trRegtestResult = Address.isP2WPKH(p2trRegtest);

            // Assert
            expect(p2pkhMainnetResult).to.be.false;
            expect(p2pkhTestnetResult).to.be.false;
            expect(p2pkhTestnetIIResult).to.be.false;
            expect(p2pkhRegtestResult).to.be.false;
            expect(p2shMainnetResult).to.be.false;
            expect(p2shTestnetResult).to.be.false;
            expect(p2shRegtestResult).to.be.false;
            expect(p2wpkhMainnetResult).to.be.true;
            expect(p2wpkhTestnetResult).to.be.true;
            expect(p2wpkhRegtestResult).to.be.true;
            expect(p2wshMainnetResult).to.be.false;
            expect(p2wshTestnetResult).to.be.false;
            expect(p2wshRegtestResult).to.be.false;
            expect(p2trMainnetResult).to.be.false;
            expect(p2trTestnetResult).to.be.false;
            expect(p2trRegtestResult).to.be.false;
        });

        it('Classify if a given address is a P2TR address correctly', () => {
            // Act
            const p2pkhMainnetResult = Address.isP2TR(p2pkhMainnet);
            const p2pkhTestnetResult = Address.isP2TR(p2pkhTestnet);
            const p2pkhTestnetIIResult = Address.isP2TR(p2pkhTestnetII);
            const p2pkhRegtestResult = Address.isP2TR(p2pkhRegtest);
            const p2shMainnetResult = Address.isP2TR(p2shMainnet);
            const p2shTestnetResult = Address.isP2TR(p2shTestnet);
            const p2shRegtestResult = Address.isP2TR(p2shRegtest);
            const p2wpkhMainnetResult = Address.isP2TR(p2wpkhMainnet);
            const p2wpkhTestnetResult = Address.isP2TR(p2wpkhTestnet);
            const p2wpkhRegtestResult = Address.isP2TR(p2wpkhRegtest);
            const p2wshMainnetResult = Address.isP2TR(p2wshMainnet);
            const p2wshTestnetResult = Address.isP2TR(p2wshTestnet);
            const p2wshRegtestResult = Address.isP2TR(p2wshRegtest);
            const p2trMainnetResult = Address.isP2TR(p2trMainnet);
            const p2trTestnetResult = Address.isP2TR(p2trTestnet);
            const p2trRegtestResult = Address.isP2TR(p2trRegtest);

            // Assert
            expect(p2pkhMainnetResult).to.be.false;
            expect(p2pkhTestnetResult).to.be.false;
            expect(p2pkhTestnetIIResult).to.be.false;
            expect(p2pkhRegtestResult).to.be.false;
            expect(p2shMainnetResult).to.be.false;
            expect(p2shTestnetResult).to.be.false;
            expect(p2shRegtestResult).to.be.false;
            expect(p2wpkhMainnetResult).to.be.false;
            expect(p2wpkhTestnetResult).to.be.false;
            expect(p2wpkhRegtestResult).to.be.false;
            expect(p2wshMainnetResult).to.be.false;
            expect(p2wshTestnetResult).to.be.false;
            expect(p2wshRegtestResult).to.be.false;
            expect(p2trMainnetResult).to.be.true;
            expect(p2trTestnetResult).to.be.true;
            expect(p2trRegtestResult).to.be.true;
        });

    });

    describe('Witness Stack Recognition Functions', () => {

        // Arrange
        // Taken from transaction 0b1941022852684d36650aff93740a4c8a0e70520f59128fa8edb23417ea7529
        const witnessP2WPKH = [
            Buffer.from('3045022100a611fcb4be51f4866e0386f44fdd83498735dd5ff37aa447ffc6243834804d1502202cf5cda352a887e0b02642492471268ecd9cb1e4ac489d047bf92838e14aaece01', 'hex'),
            Buffer.from('03d673188f8bafafc9b2819eb007901c3aef025a8fa8f74e2510f0a6c12221011c', 'hex')
        ];
        // Taken from transaction 4221ff28411a87e6d412458689c471b875dd43aca7d02c7fb7c7331855581434
        const witnessP2WSH = [
            Buffer.from('3045022100c931f9c01fe6f4e4f67c55644764659289d8d4cc723fe82dd2b97fbfda064bec02200dfd586f58c9edba874e0cef66e9fe91e7aa7a6cddd6a1f572efb66fe9caef2e01', 'hex'),
            Buffer.from('210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac', 'hex')
        ];
        // Taken from transaction 8f7805b9f578729ae8432e9711268fcbcfa02671e58ec143e40448e87281a5a0
        const witnessSingleKeyP2TR = [
            Buffer.from('f49ad81e2e586e5ad101da9c00d59fdd7397833329e5a2c5b819fb864a1f25529044df246ed045c76bbbcc39ab6739f75e17d6f85722737e20c145f9aa96338e', 'hex')
        ];
        // Taken from transaction d1042c9db36af59586e5681feeace356e85599a8fc0000cc50e263186a9c2276
        const witnessScriptP2TR = [
            Buffer.from('187d52d4ed44698ecc962ed74d7f822820475a7567c15bbad8f91ce96d0f132d2d13e43079ae700119c91a46208c995e3a18b5366368dd04450c3ff565221d2c', 'hex'),
            Buffer.from('205de8154e70d6af52906a4c4d7898b0180de5db8b7cd44cbd27cddff7751cebc7ac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d38002a7b2270223a22736e73222c226f70223a22726567222c226e616d65223a2236333132382e73617473227d68', 'hex'),
            Buffer.from('c05de8154e70d6af52906a4c4d7898b0180de5db8b7cd44cbd27cddff7751cebc7', 'hex')
        ];

        it('Classify P2WPKH witness stack correctly', () => {
            // Act
            const witnessP2WPKHResult = Address.isP2WPKHWitness(witnessP2WPKH);
            const witnessP2WSHResult = Address.isP2WPKHWitness(witnessP2WSH);
            const witnessSingleKeyP2TRResult = Address.isP2WPKHWitness(witnessSingleKeyP2TR);
            const witnessScriptP2TRResult = Address.isP2WPKHWitness(witnessScriptP2TR);

            // Assert
            expect(witnessP2WPKHResult).to.be.true;
            expect(witnessP2WSHResult).to.be.false;
            expect(witnessSingleKeyP2TRResult).to.be.false;
            expect(witnessScriptP2TRResult).to.be.false;
        });

        it('Classify single-key-spend P2TR witness stack correctly', () => {
            // Act
            const witnessP2WPKHResult = Address.isSingleKeyP2TRWitness(witnessP2WPKH);
            const witnessP2WSHResult = Address.isSingleKeyP2TRWitness(witnessP2WSH);
            const witnessSingleKeyP2TRResult = Address.isSingleKeyP2TRWitness(witnessSingleKeyP2TR);
            const witnessScriptP2TRResult = Address.isSingleKeyP2TRWitness(witnessScriptP2TR);

            // Assert
            expect(witnessP2WPKHResult).to.be.false;
            expect(witnessP2WSHResult).to.be.false;
            expect(witnessSingleKeyP2TRResult).to.be.true;
            expect(witnessScriptP2TRResult).to.be.false;
        });

    });

    it('Detect network from bitcoin network', () => {
        // Arrange
        // P2PKH
        const p2pkhMainnet = '17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem';
        const p2pkhTestnet = 'mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn';
        const p2pkhTestnetII = 'n11112Lo13n4GvQhQpDtLY8KH7KNeCVmvw';
        const p2pkhRegtest = 'mjSSLdHFzft9NC5NNMik7WrMQ9rRhMhNpT';
        // P2SH
        const p2shMainnet = '3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX';
        const p2shTestnet = '2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc';
        const p2shRegtest = '2MyQBsrfRnTLwEdpjVVYNWHDB8LXLJUcub9';
        // P2WPKH
        const p2wpkhMainnet = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
        const p2wpkhTestnet = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
        const p2wpkhRegtest = 'bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vay85cr9';
        // P2WSH
        const p2wshMainnet = 'bc1qeklep85ntjz4605drds6aww9u0qr46qzrv5xswd35uhjuj8ahfcqgf6hak';
        const p2wshTestnet = 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7';
        const p2wshRegtest = 'bcrt1qruu5mtcgx8fpz58uquwjke6tte88uykrr06nhgu9eruv2j370lesyhj9au';
        // P2TR
        const p2trMainnet = 'bc1p000022222333333444444455555555666666666999999999zz9qzagays';
        const p2trTestnet = 'tb1p000273lqsqqfw2a6h2vqxr2tll4wgtv7zu8a30rz4mhree8q5jzq8cjtyp';
        const p2trRegtest = 'bcrt1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5su3mkyy';
        // Invalid address
        const invalidAddress = 'bc1a000022222333333444444455555555666666666999999999zz9qzagays';

        // Act
        const p2pkhMainnetResult = Address.getNetworkFromAddess(p2pkhMainnet);
        const p2pkhTestnetResult = Address.getNetworkFromAddess(p2pkhTestnet);
        const p2pkhTestnetIIResult = Address.getNetworkFromAddess(p2pkhTestnetII);
        const p2pkhRegtestResult = Address.getNetworkFromAddess(p2pkhRegtest);
        const p2shMainnetResult = Address.getNetworkFromAddess(p2shMainnet);
        const p2shTestnetResult = Address.getNetworkFromAddess(p2shTestnet);
        const p2shRegtestResult = Address.getNetworkFromAddess(p2shRegtest);
        const p2wpkhMainnetResult = Address.getNetworkFromAddess(p2wpkhMainnet);
        const p2wpkhTestnetResult = Address.getNetworkFromAddess(p2wpkhTestnet);
        const p2wpkhRegtestResult = Address.getNetworkFromAddess(p2wpkhRegtest);
        const p2wshMainnetResult = Address.getNetworkFromAddess(p2wshMainnet);
        const p2wshTestnetResult = Address.getNetworkFromAddess(p2wshTestnet);
        const p2wshRegtestResult = Address.getNetworkFromAddess(p2wshRegtest);
        const p2trMainnetResult = Address.getNetworkFromAddess(p2trMainnet);
        const p2trTestnetResult = Address.getNetworkFromAddess(p2trTestnet);
        const p2trRegtestResult = Address.getNetworkFromAddess(p2trRegtest);
        const invalidAddressResult = Address.getNetworkFromAddess.bind(invalidAddress);

        // Assert
        expect(p2pkhMainnetResult).to.equal(bitcoin.networks.bitcoin);
        expect(p2pkhTestnetResult).to.equal(bitcoin.networks.testnet);
        expect(p2pkhTestnetIIResult).to.equal(bitcoin.networks.testnet);
        expect(p2pkhRegtestResult).to.equal(bitcoin.networks.testnet); // Regtest P2PKH has identical format as testnet
        expect(p2shMainnetResult).to.equal(bitcoin.networks.bitcoin);
        expect(p2shTestnetResult).to.equal(bitcoin.networks.testnet);
        expect(p2shRegtestResult).to.equal(bitcoin.networks.testnet); // Regtest P2SH has identical format as testnet
        expect(p2wpkhMainnetResult).to.equal(bitcoin.networks.bitcoin);
        expect(p2wpkhTestnetResult).to.equal(bitcoin.networks.testnet);
        expect(p2wpkhRegtestResult).to.equal(bitcoin.networks.regtest);
        expect(p2wshMainnetResult).to.equal(bitcoin.networks.bitcoin);
        expect(p2wshTestnetResult).to.equal(bitcoin.networks.testnet);
        expect(p2wshRegtestResult).to.equal(bitcoin.networks.regtest);
        expect(p2trMainnetResult).to.equal(bitcoin.networks.bitcoin);
        expect(p2trTestnetResult).to.equal(bitcoin.networks.testnet);
        expect(p2trRegtestResult).to.equal(bitcoin.networks.regtest);
        expect(invalidAddressResult).to.throws("Unknown address type");
    });

    describe('Address to scriptPubKey function', () => {

        // Arrange
        // P2PKH
        const p2pkhMainnet = '17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem';
        const p2pkhMainnetScriptPubKey = Buffer.from('76a91447376c6f537d62177a2c41c4ca9b45829ab9908388ac', 'hex');
        const p2pkhTestnet = 'mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn';
        const p2pkhTestnetScriptPubKey = Buffer.from('76a914243f1394f44554f4ce3fd68649c19adc483ce92488ac', 'hex');
        const p2pkhTestnetII = 'n11112Lo13n4GvQhQpDtLY8KH7KNeCVmvw';
        const p2pkhTestnetIIScriptPubKey = Buffer.from('76a914d5b84bc628a0a9fd15a411480198d5a31d1e5c0b88ac', 'hex');
        const p2pkhRegtest = 'mjSSLdHFzft9NC5NNMik7WrMQ9rRhMhNpT';
        const p2pkhRegtestScriptPubKey = Buffer.from('76a9142b05d564e6a7a33c087f16e0f730d1440123799d88ac', 'hex');
        // P2SH
        const p2shMainnet = '3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX';
        const p2shMainnetScriptPubKey = Buffer.from('a9148f55563b9a19f321c211e9b9f38cdf686ea0784587', 'hex');
        const p2shTestnet = '2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc';
        const p2shTestnetScriptPubKey = Buffer.from('a9144e9f39ca4688ff102128ea4ccda34105324305b087', 'hex');
        const p2shRegtest = '2MyQBsrfRnTLwEdpjVVYNWHDB8LXLJUcub9';
        const p2shRegtestScriptPubKey = Buffer.from('a9144382bc8115ce44d91b3de0d21836c6f1ecc4f85187', 'hex');
        // P2WPKH
        const p2wpkhMainnet = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
        const p2wpkhMainnetScriptPubKey = Buffer.from('0014751e76e8199196d454941c45d1b3a323f1433bd6', 'hex');
        const p2wpkhTestnet = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
        const p2wpkhTestnetScriptPubKey = Buffer.from('0014751e76e8199196d454941c45d1b3a323f1433bd6', 'hex');
        const p2wpkhRegtest = 'bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vay85cr9';
        const p2wpkhRegtestScriptPubKey = Buffer.from('00142b05d564e6a7a33c087f16e0f730d1440123799d', 'hex');
        // P2WSH
        const p2wshMainnet = 'bc1qeklep85ntjz4605drds6aww9u0qr46qzrv5xswd35uhjuj8ahfcqgf6hak';
        const p2wshMainnetScriptPubKey = Buffer.from('0020cdbf909e935c855d3e8d1b61aeb9c5e3c03ae8021b286839b1a72f2e48fdba70', 'hex');
        const p2wshTestnet = 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7';
        const p2wshTestnetScriptPubKey = Buffer.from('00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262', 'hex');
        const p2wshRegtest = 'bcrt1qruu5mtcgx8fpz58uquwjke6tte88uykrr06nhgu9eruv2j370lesyhj9au';
        const p2wshRegtestScriptPubKey = Buffer.from('00201f394daf0831d21150fc071d2b674b5e4e7e12c31bf53ba385c8f8c54a3e7ff3', 'hex');
        // P2TR
        const p2trMainnet = 'bc1p000022222333333444444455555555666666666999999999zz9qzagays';
        const p2trMainnetScriptPubKey = Buffer.from('51207bdef5294a546318c635ad6b5ad694a5294a535ad6b5ad6b45294a5294a5108a', 'hex');
        const p2trTestnet = 'tb1p000273lqsqqfw2a6h2vqxr2tll4wgtv7zu8a30rz4mhree8q5jzq8cjtyp';
        const p2trTestnetScriptPubKey = Buffer.from('51207bdeaf47e08000972bbaba98030d4bffeae42d9e170fd8bc62aeee3ce4e0a484', 'hex');
        const p2trRegtest = 'bcrt1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5su3mkyy';
        const p2trRegtestScriptPubKey = Buffer.from('51200b34f2cc6f60d54e3fdc2d1dd053fcc393bd2db9acc8de4a7c3cc28a83d4d8e9', 'hex');

        it('Convert valid Bitcoin address into correct scriptPubKey', () => {
            // Act
            const p2pkhMainnetConverted = Address.convertAdressToScriptPubkey(p2pkhMainnet);
            const p2pkhTestnetConverted = Address.convertAdressToScriptPubkey(p2pkhTestnet);
            const p2pkhTestnetIIConverted = Address.convertAdressToScriptPubkey(p2pkhTestnetII);
            const p2pkhRegtestConverted = Address.convertAdressToScriptPubkey(p2pkhRegtest);
            const p2shMainnetConverted = Address.convertAdressToScriptPubkey(p2shMainnet);
            const p2shTestnetConverted = Address.convertAdressToScriptPubkey(p2shTestnet);
            const p2shRegtestConverted = Address.convertAdressToScriptPubkey(p2shRegtest);
            const p2wpkhMainnetConverted = Address.convertAdressToScriptPubkey(p2wpkhMainnet);
            const p2wpkhTestnetConverted = Address.convertAdressToScriptPubkey(p2wpkhTestnet);
            const p2wpkhRegtestConverted = Address.convertAdressToScriptPubkey(p2wpkhRegtest);
            const p2wshMainnetConverted = Address.convertAdressToScriptPubkey(p2wshMainnet);
            const p2wshTestnetConverted = Address.convertAdressToScriptPubkey(p2wshTestnet);
            const p2wshRegtestConverted = Address.convertAdressToScriptPubkey(p2wshRegtest);
            const p2trMainnetConverted = Address.convertAdressToScriptPubkey(p2trMainnet);
            const p2trTestnetConverted = Address.convertAdressToScriptPubkey(p2trTestnet);
            const p2trRegtestConverted = Address.convertAdressToScriptPubkey(p2trRegtest);

            // Assert
            expect(p2pkhMainnetConverted).to.equalBytes(p2pkhMainnetScriptPubKey);
            expect(p2pkhTestnetConverted).to.equalBytes(p2pkhTestnetScriptPubKey);
            expect(p2pkhTestnetIIConverted).to.equalBytes(p2pkhTestnetIIScriptPubKey);
            expect(p2pkhRegtestConverted).to.equalBytes(p2pkhRegtestScriptPubKey);
            expect(p2shMainnetConverted).to.equalBytes(p2shMainnetScriptPubKey);
            expect(p2shTestnetConverted).to.equalBytes(p2shTestnetScriptPubKey);
            expect(p2shRegtestConverted).to.equalBytes(p2shRegtestScriptPubKey);
            expect(p2wpkhMainnetConverted).to.equalBytes(p2wpkhMainnetScriptPubKey);
            expect(p2wpkhTestnetConverted).to.equalBytes(p2wpkhTestnetScriptPubKey);
            expect(p2wpkhRegtestConverted).to.equalBytes(p2wpkhRegtestScriptPubKey);
            expect(p2wshMainnetConverted).to.equalBytes(p2wshMainnetScriptPubKey);
            expect(p2wshTestnetConverted).to.equalBytes(p2wshTestnetScriptPubKey);
            expect(p2wshRegtestConverted).to.equalBytes(p2wshRegtestScriptPubKey);
            expect(p2trMainnetConverted).to.equalBytes(p2trMainnetScriptPubKey);
            expect(p2trTestnetConverted).to.equalBytes(p2trTestnetScriptPubKey);
            expect(p2trRegtestConverted).to.equalBytes(p2trRegtestScriptPubKey);
        });

        it('Throw when handling invalid address', () => {
            // Arrange
            const p2pkhMainnetMalformed = p2pkhMainnet + 'm';
            const p2pkhTestnetMalformed = p2pkhTestnet + 'm';
            const p2pkhRegtestMalformed = p2pkhRegtest + 'm';
            const p2shMainnetMalformed = p2shMainnet + 'm';
            const p2shTestnetMalformed = p2shTestnet + 'm';
            const p2shRegtestMalformed = p2shRegtest + 'm';
            const p2wpkhMainnetMalformed = p2wpkhMainnet + 'm';
            const p2wpkhTestnetMalformed = p2wpkhTestnet + 'm';
            const p2wpkhRegtestMalformed = p2wpkhRegtest + 'm';
            const p2wshMainnetMalformed = p2wshMainnet + 'm';
            const p2wshTestnetMalformed = p2wshTestnet + 'm';
            const p2wshRegtestMalformed = p2wshRegtest + 'm';
            const p2trMainnetMalformed = p2trMainnet + 'm';
            const p2trTestnetMalformed = p2trTestnet + 'm';
            const p2trRegtestMalformed = p2trRegtest + 'm';
            const p2wtfMalformed = 'bc1wtfpv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3';

            // Act
            const p2pkhMainnetMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2pkhMainnetMalformed);
            const p2pkhTestnetMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2pkhTestnetMalformed);
            const p2pkhRegtestMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2pkhRegtestMalformed);
            const p2shMainnetMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2shMainnetMalformed);
            const p2shTestnetMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2shTestnetMalformed);
            const p2shRegtestMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2shRegtestMalformed);
            const p2wpkhMainnetMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2wpkhMainnetMalformed);
            const p2wpkhTestnetMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2wpkhTestnetMalformed);
            const p2wpkhRegtestMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2wpkhRegtestMalformed);
            const p2wshMainnetMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2wshMainnetMalformed);
            const p2wshTestnetMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2wshTestnetMalformed);
            const p2wshRegtestMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2wshRegtestMalformed);
            const p2trMainnetMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2trMainnetMalformed);
            const p2trTestnetMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2trTestnetMalformed);
            const p2trRegtestMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2trRegtestMalformed);
            const p2wtfMalformedResult = Address.convertAdressToScriptPubkey.bind(Address, p2wtfMalformed);

            // Assert
            expect(p2pkhMainnetMalformedResult).to.throw(); // Throw by bitcoinjs-message library
            expect(p2pkhTestnetMalformedResult).to.throw(); // Throw by bitcoinjs-message library
            expect(p2pkhRegtestMalformedResult).to.throw(); // Throw by bitcoinjs-message library
            expect(p2shMainnetMalformedResult).to.throw(); // Throw by bitcoinjs-message library
            expect(p2shTestnetMalformedResult).to.throw(); // Throw by bitcoinjs-message library
            expect(p2shRegtestMalformedResult).to.throw(); // Throw by bitcoinjs-message library
            expect(p2wpkhMainnetMalformedResult).to.throws('Unknown address type');
            expect(p2wpkhTestnetMalformedResult).to.throws('Unknown address type');
            expect(p2wpkhRegtestMalformedResult).to.throws('Unknown address type');
            expect(p2wshMainnetMalformedResult).to.throws('Unknown address type');
            expect(p2wshTestnetMalformedResult).to.throws('Unknown address type');
            expect(p2wshRegtestMalformedResult).to.throws('Unknown address type');
            expect(p2trMainnetMalformedResult).to.throws('Unknown address type');
            expect(p2trTestnetMalformedResult).to.throws('Unknown address type');
            expect(p2trRegtestMalformedResult).to.throws('Unknown address type');
            expect(p2wtfMalformedResult).to.throws('Unknown address type');
        });

    });

    describe('Public Key to Addres Function', () => {

        it('Convert valid public key into correct Bitcoin address', () => {
            // Arrange
            // Extract public key from private key
            const privateKey = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
            const ECPair = ECPairFactory(ecc);
            const signer = ECPair.fromWIF(privateKey);
            const publicKey = signer.publicKey;
            // Expected address for the private key L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k
            const p2pkhAddress = '14vV3aCHBeStb5bkenkNHbe2YAFinYdXgc';
            const p2pkhAddressTestnet = 'mjSSLdHFzft9NC5NNMik7WrMQ9rRhMhNpT';
            const p2pkhAddressRegtest = 'mjSSLdHFzft9NC5NNMik7WrMQ9rRhMhNpT';
            const p2shAddress = '37qyp7jQAzqb2rCBpMvVtLDuuzKAUCVnJb';
            const p2shAddressTestnet = '2MyQBsrfRnTLwEdpjVVYNWHDB8LXLJUcub9';
            const p2shAddressRegtest = '2MyQBsrfRnTLwEdpjVVYNWHDB8LXLJUcub9';
            const p2wpkhAddress = 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l';
            const p2wpkhAddressTestnet = 'tb1q9vza2e8x573nczrlzms0wvx3gsqjx7vaxwd45v';
            const p2wpkhAddressRegtest = 'bcrt1q9vza2e8x573nczrlzms0wvx3gsqjx7vay85cr9';
            const p2trAddress = 'bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3';
            const p2trAddressTestnet = 'tb1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5s3g3s37';
            const p2trAddressRegtest = 'bcrt1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5su3mkyy';

            // Act
            const p2pkhAddressGenerated = Address.convertPubKeyIntoAddress(publicKey, 'p2pkh');
            const p2shAddressGenerated = Address.convertPubKeyIntoAddress(publicKey, 'p2sh-p2wpkh');
            const p2wpkhAddressGenerated = Address.convertPubKeyIntoAddress(publicKey, 'p2wpkh');
            const p2trAddressGenerated = Address.convertPubKeyIntoAddress(publicKey, 'p2tr');
            const p2trAddressGeneratedInternalPubKey = Address.convertPubKeyIntoAddress(publicKey.subarray(1, 33), 'p2tr');

            // Assert
            expect(p2pkhAddressGenerated.mainnet).to.equal(p2pkhAddress);
            expect(p2pkhAddressGenerated.testnet).to.equal(p2pkhAddressTestnet);
            expect(p2pkhAddressGenerated.regtest).to.equal(p2pkhAddressRegtest);
            expect(p2shAddressGenerated.mainnet).to.equal(p2shAddress);
            expect(p2shAddressGenerated.testnet).to.equal(p2shAddressTestnet);
            expect(p2shAddressGenerated.regtest).to.equal(p2shAddressRegtest);
            expect(p2wpkhAddressGenerated.mainnet).to.equal(p2wpkhAddress);
            expect(p2wpkhAddressGenerated.testnet).to.equal(p2wpkhAddressTestnet);
            expect(p2wpkhAddressGenerated.regtest).to.equal(p2wpkhAddressRegtest);
            expect(p2trAddressGenerated.mainnet).to.equal(p2trAddress);
            expect(p2trAddressGenerated.testnet).to.equal(p2trAddressTestnet);
            expect(p2trAddressGenerated.regtest).to.equal(p2trAddressRegtest);
            expect(p2trAddressGeneratedInternalPubKey.mainnet).to.equal(p2trAddress);
            expect(p2trAddressGeneratedInternalPubKey.testnet).to.equal(p2trAddressTestnet);
            expect(p2trAddressGeneratedInternalPubKey.regtest).to.equal(p2trAddressRegtest);
        });

        it('Throw when handling invalid address type', () => {
            // Arrange
            // Extract public key from private key
            const privateKey = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
            const ECPair = ECPairFactory(ecc);
            const signer = ECPair.fromWIF(privateKey);
            const publicKey = signer.publicKey;

            // Act
            // @ts-ignore
            const p2wtfAddress = Address.convertPubKeyIntoAddress.bind(publicKey, 'p2wtf');

            // Assert
            expect(p2wtfAddress).to.throws('Cannot convert public key into unsupported address type.');
        });

    });

    describe('Bitcoin Address Validation Tests', function() {

        // Test valid mainnet addresses
        it('Return true for valid mainnet addresses', function() {
            // Arrange
            const mainnetP2PKHAddress = '1K6KoYC69NnafWJ7YgtrpwJxBLiijWqwa6';
            const mainnetP2SHAddress = '3CVQuRpFMnDV71ABpXNg9yhUpgsWL1L8y6';
            const mainnetP2WPKHAddress = 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l';
            const mainnetP2TRAddress = 'bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3';
            // Act and Assert
            expect(Address.isValidBitcoinAddress(mainnetP2PKHAddress)).to.be.true;
            expect(Address.isValidBitcoinAddress(mainnetP2SHAddress)).to.be.true;
            expect(Address.isValidBitcoinAddress(mainnetP2WPKHAddress)).to.be.true;
            expect(Address.isValidBitcoinAddress(mainnetP2TRAddress)).to.be.true;
        });
      
        // Test valid testnet addresses
        it('Return true for valid testnet addresses', function() {
            // Arrange
            const testnetP2PKHAddress = 'mjSSLdHFzft9NC5NNMik7WrMQ9rRhMhNpT';
            const testnetP2SHAddress = '2MyQBsrfRnTLwEdpjVVYNWHDB8LXLJUcub9';
            const testnetP2WPKHAddress = 'tb1q9vza2e8x573nczrlzms0wvx3gsqjx7vaxwd45v';
            const testnetP2TRAddress = 'tb1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5s3g3s37';
            // Act and Assert
            expect(Address.isValidBitcoinAddress(testnetP2PKHAddress)).to.be.true;
            expect(Address.isValidBitcoinAddress(testnetP2SHAddress)).to.be.true;
            expect(Address.isValidBitcoinAddress(testnetP2WPKHAddress)).to.be.true;
            expect(Address.isValidBitcoinAddress(testnetP2TRAddress)).to.be.true;
        });
      
        // Test valid regtest addresses
        it('Return true for valid regtest addresses', function() {
            // Arrange
            const regtestP2PKHAddress = 'msiGFK1PjCk8E6FXeoGkQPTscmcpyBdkgS';
            const regtestP2SHAddress = '2NEb8N5B9jhPUCBchz16BB7bkJk8VCZQjf3';
            const regtestP2WPKHAddress = 'bcrt1q39c0vrwpgfjkhasu5mfke9wnym45nydfwaeems';
            const regtestP2TRAddress = 'bcrt1pema6mzjsr3849rg5e5ls9lfck46zc3muph65rmskt28ravzzzxwsz99c2q';
            // Act and Assert
            expect(Address.isValidBitcoinAddress(regtestP2PKHAddress)).to.be.true;
            expect(Address.isValidBitcoinAddress(regtestP2SHAddress)).to.be.true;
            expect(Address.isValidBitcoinAddress(regtestP2WPKHAddress)).to.be.true;
            expect(Address.isValidBitcoinAddress(regtestP2TRAddress)).to.be.true;
        });
      
        // Test invalid addresses
        it('Return false for invalid addresses', function() {
            // Arrange
            const invalidAddressMainnet = '1K6KoYC69NnafWJ7YgtrpwJxBLiijWqwa5'; // From 1K6KoYC69NnafWJ7YgtrpwJxBLiijWqwa6
            const invalidAddressMainnetTwo = 'bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt2'; // From bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3
            const invalidAddressTesnet = '2MyQBsrfRnTLwEdpjVVYNWHDB8LXLJUcub1'; // From 2MyQBsrfRnTLwEdpjVVYNWHDB8LXLJUcub9
            const invalidAddressRegtest = 'bcrt1q39c0vrwpgfjkhasu5mfke9wnym45nydfwaeema'; // From bcrt1q39c0vrwpgfjkhasu5mfke9wnym45nydfwaeems
            // Act and Assert
            expect(Address.isValidBitcoinAddress(invalidAddressMainnet)).to.be.false;
            expect(Address.isValidBitcoinAddress(invalidAddressMainnetTwo)).to.be.false;
            expect(Address.isValidBitcoinAddress(invalidAddressTesnet)).to.be.false;
            expect(Address.isValidBitcoinAddress(invalidAddressRegtest)).to.be.false;
        });
      
    });

});