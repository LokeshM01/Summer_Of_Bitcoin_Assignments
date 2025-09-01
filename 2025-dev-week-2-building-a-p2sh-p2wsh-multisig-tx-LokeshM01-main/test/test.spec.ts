import {readFileSync} from "fs";
import { Script, TX, Coin, CoinView} from 'bcoin';

describe('Evaluate submission', () => {
    let txHex: any;
    let tx: any;
    const address = '325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF'

    it('should check if txHex is defined', () => {
        // read txid from out.txt
        const data = readFileSync('out.txt', 'utf8');
        txHex = data.trim();
        expect(txHex).toBeDefined();
        expect(txHex.length).toBeGreaterThan(0);
    });

    it('should parse serialised tx', () => {
        tx = TX.fromRaw(txHex, 'hex');
        expect(tx).toBeDefined();
    });

    it('should have only 1 input', () => {
        expect(tx.inputs.length).toBe(1);
    });

    it('should have correct prevout in input', () => {
        expect(tx.inputs[0].prevout.hash.toString('hex')).toBe('0000000000000000000000000000000000000000000000000000000000000000')
        expect(tx.inputs[0].prevout.index).toBe(0)
    });

    it('should have correct sequence in input', () => {
        expect(tx.inputs[0].sequence).toBe(0xffffffff)
    });

    it('should spend from expected address', () => {
        expect(tx.inputs[0].getAddress().toString()).toBe(address);
    });

    it('should have expected redeem script in input', () => {
        expect(tx.inputs[0].getRedeem().toRaw().toString('hex')).toBe('5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae');
    });

    it('should have only 1 output', () => {
        expect(tx.outputs.length).toBe(1);
    });

    it('should have expected output value', () => {
        expect(tx.outputs[0].value).toBe(100000);
    });

    it('should have expected output address', () => {
        expect(tx.outputs[0].getAddress().toString()).toBe(address);
    });

    it('should have correct locktime', () => {
        expect(tx.locktime).toBe(0);
    });

    it('should pass signature checks', () => {
        const coin = new Coin({
            version: 2,
            height: 0,
            value: 100000,
            script: Script.fromAddress(address),
            coinbase: false,
            hash: Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
            index: 0,
        });
        const coinView = new CoinView();
        coinView.addCoin(coin);
        expect(tx.verify(coinView)).toBe(true);
    });
});