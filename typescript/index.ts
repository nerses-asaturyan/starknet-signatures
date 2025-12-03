import * as readline from 'readline';
import { hkdfSync } from 'crypto';

// --- Generic key derivation helpers (chain‑agnostic) ---

const INFO = Buffer.from('generic-signature-key-derivation', 'utf8');
const KEY_LENGTH = 32; // 256 bits

// Normalize hex string: remove 0x prefix if present
function normalizeHex(hex: string): string {
    return hex.startsWith('0x') ? hex.slice(2) : hex;
}

// Convert arbitrary input (Buffer or hex string) to Buffer
function toBuffer(input: Buffer | string): Buffer {
    if (Buffer.isBuffer(input)) return input;
    const clean = normalizeHex(input);
    return Buffer.from(clean, 'hex');
}

/**
 * Create an initial key from a signature and a chainId.
 * - `signature` can be an Ethereum ECDSA signature, Starknet signature, or any other chain's signature, as hex or Buffer.
 * - `chainId` should be a hex string or Buffer representing signature's chainId.
 */
export function createInitialKeyFromSignature(
    signature: Buffer | string,
    chainId: Buffer | string,
): string {
    const sigBuf = toBuffer(signature);
    const chainIdBuf = toBuffer(chainId);

    const keyBuf = hkdfSync('sha256', sigBuf as any, chainIdBuf as any, INFO as any, KEY_LENGTH);
    return '0x' + (keyBuf as any).toString('hex');
}

/**
 * Derive a key from an initial key and a timelock value.
 * - `initialKey` is the hex or Buffer returned by `createInitialKeyFromSignature`.
 * - `timelock` is typically a Unix timestamp or any monotonically increasing value (number or bigint).
 */
export function deriveKeyFromInitialKeyAndTimelock(
    initialKey: Buffer | string,
    timelock: bigint | number | string,
): string {
    const keyBuf = toBuffer(initialKey);

    let timeBig: bigint;
    if (typeof timelock === 'bigint') {
        timeBig = timelock;
    } else if (typeof timelock === 'number') {
        timeBig = BigInt(timelock);
    } else {
        // string – allow decimal or hex with 0x
        if (timelock.startsWith('0x')) {
            timeBig = BigInt(timelock);
        } else {
            timeBig = BigInt(timelock);
        }
    }

    const timeHex = timeBig.toString(16);
    const timeBuf = Buffer.from(timeHex.length % 2 === 0 ? timeHex : '0' + timeHex, 'hex');

    const derivedBuf = hkdfSync('sha256', keyBuf as any, timeBuf as any, INFO as any, KEY_LENGTH);
    return '0x' + (derivedBuf as any).toString('hex');
}

// --- Optional CLI for manual testing ---

function askQuestion(query: string): Promise<string> {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });

    return new Promise((resolve) => {
        rl.question(query, (answer) => {
            rl.close();
            resolve(answer.trim());
        });
    });
}

async function main() {
    console.log('=== Generic Signature → Key Derivation Tool ===\n');

    // Get signature and chainId (e.g. chain id) from the user
    const signatureHex = await askQuestion('Enter signature (hex, e.g. Ethereum 0x...): ');
    const chainIdHex = await askQuestion('Enter chainId');

    const initialKey = createInitialKeyFromSignature(signatureHex, chainIdHex);
    console.log('\nInitial key:', initialKey);

    while (true) {
        console.log('\nOptions:');
        console.log('  1) Derive key from initial key and timelock');
        console.log('  2) Exit');

        const choice = await askQuestion('Choose an option (1/2): ');

        if (choice === '2') {
            console.log('\nDone.');
            break;
        } else if (choice === '1') {
            const tInput = await askQuestion(
                'Enter timelock (Unix timestamp or bigint, decimal or 0x...): ',
            );

            try {
                const derivedKey = deriveKeyFromInitialKeyAndTimelock(initialKey, tInput);
                console.log('\nDerived key:', derivedKey);
            } catch (err) {
                console.error('Error deriving key:', err);
            }
        } else {
            console.log('Invalid choice. Please enter 1 or 2.');
        }
    }
}

main()