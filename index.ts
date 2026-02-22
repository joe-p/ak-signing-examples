import { mnemonicFromSeed, seedFromMnemonic } from "@algorandfoundation/algokit-utils/algo25";
import {
  nobleEd25519Generator,
  nobleEd25519Verifier,
  RawEd25519Signer,
} from "@algorandfoundation/algokit-utils/crypto";
import { getLinuxMnemonic, setLinuxMnemonic } from "./linux";
import { getMacMnemonic, setMacMnemonic } from "./mac";
import { getWindowsMnemonic, setWindowsMnemonic } from "./win";
import { generateAddressWithSigners } from "@algorandfoundation/algokit-utils/transact";

function getMnemonicForPlatform(name: string): string {
  if (process.platform === "darwin") return getMacMnemonic(name);
  if (process.platform === "linux") return getLinuxMnemonic(name);
  if (process.platform === "win32") return getWindowsMnemonic(name);
  throw new Error(`Unsupported platform: ${process.platform}`);
}

function setMnemonicForPlatform(name: string, mnemonic: string): void {
  if (process.platform === "darwin") {
    setMacMnemonic(name, mnemonic);
    return;
  }
  if (process.platform === "linux") {
    setLinuxMnemonic(name, mnemonic);
    return;
  }
  if (process.platform === "win32") {
    setWindowsMnemonic(name, mnemonic);
    return;
  }
  throw new Error(`Unsupported platform: ${process.platform}`);
}

const MNEMONIC_NAME = "algorand-mainnet-mnemonic";

export const rawEd25519Signer: RawEd25519Signer = async (data: Uint8Array): Promise<Uint8Array> => {
  const mnemonic = getMnemonicForPlatform(MNEMONIC_NAME);
  const seed = seedFromMnemonic(mnemonic);
  const { rawEd25519Signer } = nobleEd25519Generator(seed);

  const sig = await rawEd25519Signer(data);
  seed.fill(0);

  return sig;
};

export const getPubkey = (): Uint8Array => {
  const mnemonic = getMnemonicForPlatform(MNEMONIC_NAME);
  const seed = seedFromMnemonic(mnemonic);
  const { ed25519Pubkey } = nobleEd25519Generator(seed);
  seed.fill(0);

  return ed25519Pubkey;
}

const algorandAccount = generateAddressWithSigners({ rawEd25519Signer, ed25519Pubkey: getPubkey() });

// Demo
const seed = crypto.getRandomValues(new Uint8Array(32));
const mnemonic = mnemonicFromSeed(seed);
const acct = nobleEd25519Generator(seed);

setMnemonicForPlatform(MNEMONIC_NAME, mnemonic);

const data = new Uint8Array([1, 2, 3]);
const sig = await rawEd25519Signer(data);
const isValid = await nobleEd25519Verifier(sig, data, acct.ed25519Pubkey);

if (!isValid) {
  console.error("Signature verification failed");
  process.exit(1);
}

console.log("Signature valid?", isValid);
