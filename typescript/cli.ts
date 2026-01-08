import * as readline from "readline";
import { createInitialKeyFromSignature, deriveKeyFromInitialKeyAndTimelock } from "./index.js";

function askQuestion(query: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(query, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

async function main() {
  console.log("=== Signature Key Derivation Tool ===\n");
  console.log("Notes:");
  console.log("- signature: hex bytes (0x...)");
  console.log('- chainId: numeric only: decimal like "1" or hex like "0x1"');
  console.log('- timelock: decimal or 0x-hex; default encoding is uint64 BE (8 bytes)\n');

  const signatureHex = await askQuestion("Enter signature (hex, e.g. 0x1234...): ");
  const chainIdInput = await askQuestion('Enter numeric chain ID (decimal like "1" or hex like "0x1"): ');

  try {
    const initialKey = createInitialKeyFromSignature(signatureHex, chainIdInput);
    console.log("\nInitial key:", initialKey);

    while (true) {
      console.log("\nOptions:");
      console.log("  1) Derive key from initial key and timelock");
      console.log("  2) Exit");

      const choice = await askQuestion("Choose an option (1/2): ");

      if (choice === "2") {
        console.log("\nDone.");
        break;
      } else if (choice === "1") {
        const tInput = await askQuestion("Enter timelock (Unix timestamp, decimal or 0x hex): ");
        try {
          const derivedKey = deriveKeyFromInitialKeyAndTimelock(initialKey, tInput);
          console.log("\nDerived key:", derivedKey);
        } catch (err) {
          console.error("Error deriving key:", err instanceof Error ? err.message : String(err));
        }
      } else {
        console.log("Invalid choice. Please enter 1 or 2.");
      }
    }
  } catch (err) {
    console.error("\nError:", err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
