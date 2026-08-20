import { expect } from 'chai';
import { withReplacedProperty } from './ReplaceProperty';

describe('withReplacedProperty', () => {

    it('Restore the original descriptor after a successful callback', () => {
        const target: { value: number } = { value: 1 };
        const original = Object.getOwnPropertyDescriptor(target, 'value');

        const result = withReplacedProperty(target, 'value', 99, () => {
            expect(target.value).to.equal(99);
            return 'ok';
        });

        expect(result).to.equal('ok');
        expect(Object.getOwnPropertyDescriptor(target, 'value')).to.deep.equal(original);
        expect(target.value).to.equal(1);
    });

    it('Restore the original descriptor after a callback that throws', () => {
        const target: { value: number } = { value: 1 };
        const original = Object.getOwnPropertyDescriptor(target, 'value');

        expect(() => {
            withReplacedProperty(target, 'value', 99, () => {
                expect(target.value).to.equal(99);
                throw new Error('boom');
            });
        }).to.throw('boom');

        expect(Object.getOwnPropertyDescriptor(target, 'value')).to.deep.equal(original);
        expect(target.value).to.equal(1);
    });

    it('Throw when the property is missing', () => {
        const target = {};
        expect(() => {
            withReplacedProperty(target, 'missing', 1, () => undefined);
        }).to.throw('Property missing is missing and cannot be replaced.');
    });

    it('Throw when the property is not configurable', () => {
        const target = {};
        Object.defineProperty(target, 'locked', {
            configurable: false,
            enumerable: true,
            writable: true,
            value: 1
        });
        expect(() => {
            withReplacedProperty(target, 'locked', 2, () => undefined);
        }).to.throw('Property locked is not configurable and cannot be replaced.');
    });

});
