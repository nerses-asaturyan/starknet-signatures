import { createInitialKeyFromSignature, deriveKeyFromInitialKeyAndTimelock } from '../index.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);

/**
 * Test suite for key derivation functions.
 * Run with: npm test or ts-node tests/index.test.ts
 */

function runTests() {
    console.log('Running test suite...\n');
    let passedTests = 0;
    let failedTests = 0;

    function test(name: string, fn: () => void) {
        try {
            fn();
            console.log(`✓ ${name}`);
            passedTests++;
        } catch (err) {
            console.error(`✗ ${name}`);
            console.error(`  ${err instanceof Error ? err.message : String(err)}`);
            failedTests++;
        }
    }

    // Test 1: Determinism
    test('Same inputs produce same output', () => {
        const sig = '0x' + 'aa'.repeat(32);
        const chain = '1';
        const key1 = createInitialKeyFromSignature(sig, chain);
        const key2 = createInitialKeyFromSignature(sig, chain);
        if (key1 !== key2) {
            throw new Error('Expected identical outputs for identical inputs');
        }
    });

    // Test 2: Chain ID separation
    test('Different chain IDs produce different keys', () => {
        const sig = '0x' + 'aa'.repeat(32);
        const key1 = createInitialKeyFromSignature(sig, '1');
        const key2 = createInitialKeyFromSignature(sig, '2');
        if (key1 === key2) {
            throw new Error('Expected different outputs for different chain IDs');
        }
    });

    // Test 3: Chain ID format equivalence
    test('Decimal and hex chain IDs produce same key', () => {
        const sig = '0x' + 'aa'.repeat(32);
        const key1 = createInitialKeyFromSignature(sig, '255');
        const key2 = createInitialKeyFromSignature(sig, '0xff');
        if (key1 !== key2) {
            throw new Error('Expected same output for 255 and 0xff');
        }
    });

    // Test 4: Timelock separation
    test('Different timelocks produce different keys', () => {
        const sig = '0x' + 'aa'.repeat(32);
        const initialKey = createInitialKeyFromSignature(sig, '1');
        const key1 = deriveKeyFromInitialKeyAndTimelock(initialKey, 1000);
        const key2 = deriveKeyFromInitialKeyAndTimelock(initialKey, 2000);
        if (key1 === key2) {
            throw new Error('Expected different outputs for different timelocks');
        }
    });

    // Test 5: Timelock format equivalence
    test('Decimal and hex timelocks produce same key', () => {
        const sig = '0x' + 'aa'.repeat(32);
        const initialKey = createInitialKeyFromSignature(sig, '1');
        const key1 = deriveKeyFromInitialKeyAndTimelock(initialKey, '255');
        const key2 = deriveKeyFromInitialKeyAndTimelock(initialKey, '0xff');
        if (key1 !== key2) {
            throw new Error('Expected same output for 255 and 0xff');
        }
    });

    // Test 6: Empty hex string rejection
    test('Rejects empty hex string', () => {
        try {
            createInitialKeyFromSignature('0x', '1');
            throw new Error('Should have thrown');
        } catch (err) {
            if (!(err instanceof Error && err.message.includes('empty'))) {
                throw new Error('Expected empty error');
            }
        }
    });

    // Test 7: Odd-length hex rejection
    test('Rejects odd-length hex string', () => {
        try {
            createInitialKeyFromSignature('0xaaa', '1');
            throw new Error('Should have thrown');
        } catch (err) {
            if (!(err instanceof Error && err.message.includes('even length'))) {
                throw new Error('Expected even length error');
            }
        }
    });

    // Test 8: Invalid hex characters rejection
    test('Rejects invalid hex characters', () => {
        try {
            createInitialKeyFromSignature('0xGGGG', '1');
            throw new Error('Should have thrown');
        } catch (err) {
            if (!(err instanceof Error && (err.message.includes('invalid') || err.message.includes('Invalid')))) {
                throw new Error(`Expected invalid characters error, got: ${err instanceof Error ? err.message : String(err)}`);
            }
        }
    });

    // Test 9: Short signature rejection
    test('Rejects signature shorter than 32 bytes', () => {
        try {
            createInitialKeyFromSignature('0xaa', '1');
            throw new Error('Should have thrown');
        } catch (err) {
            if (!(err instanceof Error && err.message.includes('at least'))) {
                throw new Error('Expected minimum length error');
            }
        }
    });

    // Test 10: Non-numeric chain ID rejection
    test('Rejects non-numeric chain ID strings', () => {
        const sig = '0x' + 'aa'.repeat(32);
        try {
            createInitialKeyFromSignature(sig, 'solana:mainnet-beta');
            throw new Error('Should have thrown');
        } catch (err) {
            if (!(err instanceof Error && err.message.includes('numeric'))) {
                throw new Error('Expected numeric error');
            }
        }
    });

    // Test 11: Negative timelock rejection
    test('Rejects negative timelock', () => {
        const sig = '0x' + 'aa'.repeat(32);
        const initialKey = createInitialKeyFromSignature(sig, '1');
        try {
            deriveKeyFromInitialKeyAndTimelock(initialKey, -100);
            throw new Error('Should have thrown');
        } catch (err) {
            if (!(err instanceof Error && err.message.includes('negative'))) {
                throw new Error('Expected negative error');
            }
        }
    });

    // Test 12: Non-integer timelock rejection
    test('Rejects non-integer timelock', () => {
        const sig = '0x' + 'aa'.repeat(32);
        const initialKey = createInitialKeyFromSignature(sig, '1');
        try {
            deriveKeyFromInitialKeyAndTimelock(initialKey, 1.5);
            throw new Error('Should have thrown');
        } catch (err) {
            if (!(err instanceof Error && err.message.includes('integer'))) {
                throw new Error('Expected integer error');
            }
        }
    });

    // Test 13: Wrong key length rejection
    test('Rejects initial key with wrong length', () => {
        try {
            deriveKeyFromInitialKeyAndTimelock('0xaa', 1000);
            throw new Error('Should have thrown');
        } catch (err) {
            if (!(err instanceof Error && err.message.includes('exactly'))) {
                throw new Error('Expected exact length error');
            }
        }
    });

    // Test 14: Too-long initial key rejection
    test('Rejects initial key longer than 32 bytes', () => {
        const tooLongKey = '0x' + 'aa'.repeat(33); // 33 bytes
        try {
            deriveKeyFromInitialKeyAndTimelock(tooLongKey, 1000);
            throw new Error('Should have thrown');
        } catch (err) {
            if (!(err instanceof Error && err.message.includes('exactly'))) {
                throw new Error('Expected exact length error for long key');
            }
        }
    });

    // Test 15: Output format validation
    test('Output keys are properly formatted', () => {
        const sig = '0x' + 'aa'.repeat(32);
        const key1 = createInitialKeyFromSignature(sig, '1');
        const key2 = deriveKeyFromInitialKeyAndTimelock(key1, 1000);
        
        if (!key1.startsWith('0x') || key1.length !== 66) {
            throw new Error('Initial key format invalid');
        }
        if (!key2.startsWith('0x') || key2.length !== 66) {
            throw new Error('Derived key format invalid');
        }
    });

    // Test 16: Alternate 16-byte key length behaves deterministically and formats correctly
    test('Supports 16-byte keys when key length is changed', () => {
        const sig = '0x' + 'ab'.repeat(32);
        const chain = '42';

        const key1 = createInitialKeyFromSignature(sig, chain, { outputLength: 16 });
        const key2 = createInitialKeyFromSignature(sig, chain, { outputLength: 16 });

        if (key1 !== key2) {
            throw new Error('16-byte initial keys should be deterministic');
        }
        if (key1.length !== 34) {
            throw new Error('16-byte initial key should be 0x + 32 hex chars');
        }

        const derived1 = deriveKeyFromInitialKeyAndTimelock(key1, 1234, { outputLength: 16 });
        const derived2 = deriveKeyFromInitialKeyAndTimelock(key1, 1234, { outputLength: 16 });

        if (derived1 !== derived2) {
            throw new Error('16-byte derived keys should be deterministic');
        }
        if (derived1.length !== 34) {
            throw new Error('16-byte derived key should be 0x + 32 hex chars');
        }
    });

    // Test 17: Custom chainIdWidth and timelockWidth change output but remain deterministic
    test('Custom chainIdWidth and timelockWidth change output deterministically', () => {
        const sig = '0x' + 'cd'.repeat(32);

        const keyDefault = createInitialKeyFromSignature(sig, '5');
        const keyWidth8a = createInitialKeyFromSignature(sig, '5', { chainIdWidth: 8 });
        const keyWidth8b = createInitialKeyFromSignature(sig, '5', { chainIdWidth: 8 });

        if (keyWidth8a !== keyWidth8b) {
            throw new Error('Custom chainIdWidth should be deterministic');
        }
        if (keyDefault === keyWidth8a) {
            throw new Error('Changing chainIdWidth should change derived key material');
        }

        const derivedDefault = deriveKeyFromInitialKeyAndTimelock(keyWidth8a, 1000);
        const derivedWidth4a = deriveKeyFromInitialKeyAndTimelock(keyWidth8a, 1000, { timelockWidth: 4 });
        const derivedWidth4b = deriveKeyFromInitialKeyAndTimelock(keyWidth8a, 1000, { timelockWidth: 4 });

        if (derivedWidth4a !== derivedWidth4b) {
            throw new Error('Custom timelockWidth should be deterministic');
        }
        if (derivedDefault === derivedWidth4a) {
            throw new Error('Changing timelockWidth should change derived key material');
        }
    });

    // Test 18: Regression guard for default key length 
    test('Default key length remains 32 bytes (0x + 64 hex chars)', () => {
        const sig = '0x' + 'ee'.repeat(32);
        const key = createInitialKeyFromSignature(sig, '7');
        if (key.length !== 66) {
            throw new Error('Default initial key should be 32 bytes (0x + 64 hex chars)');
        }
        const derived = deriveKeyFromInitialKeyAndTimelock(key, 999);
        if (derived.length !== 66) {
            throw new Error('Default derived key should be 32 bytes (0x + 64 hex chars)');
        }
    });

    console.log(`\n${passedTests} passed, ${failedTests} failed`);
    
    if (failedTests > 0) {
        process.exit(1);
    }
}

if (process.argv[1] === __filename || process.argv[1]?.endsWith(path.basename(__filename))) {
    runTests();
}