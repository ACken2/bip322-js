/**
 * Temporarily replace a configurable own property and restore its original descriptor.
 *
 * @param object Object that owns the property
 * @param key Property name to replace
 * @param value Replacement value installed as a configurable data property
 * @param callback Function executed while the replacement is in effect
 * @returns The callback's return value
 */
export function withReplacedProperty<T extends object, K extends PropertyKey, R>(
    object: T,
    key: K,
    value: unknown,
    callback: () => R
): R {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (!descriptor) {
        throw new Error(`Property ${String(key)} is missing and cannot be replaced.`);
    }
    if (!descriptor.configurable) {
        throw new Error(`Property ${String(key)} is not configurable and cannot be replaced.`);
    }
    Object.defineProperty(object, key, {
        configurable: true,
        enumerable: descriptor.enumerable,
        writable: true,
        value
    });
    try {
        return callback();
    }
    finally {
        Object.defineProperty(object, key, descriptor);
    }
}
