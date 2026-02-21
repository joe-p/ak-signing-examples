import { mnemonicFromSeed, seedFromMnemonic } from "@algorandfoundation/algokit-utils/algo25";
import {
  nobleEd25519Generator,
  nobleEd25519Verifier,
  RawEd25519Signer,
} from "@algorandfoundation/algokit-utils/crypto";
import { execFileSync } from "child_process";

const MNEMONIC_NAME = "algorand-mainnet-mnemonic";

function run(cmd: string, args: string[]): string {
  return execFileSync(cmd, args, { encoding: "utf-8" }).trim();
}

function getMacMnemonic(): string {
  const user = process.env.USER ?? "";
  if (!user) throw new Error("USER is not set");
  return run("security", ["find-generic-password", "-a", user, "-s", MNEMONIC_NAME, "-w"]);
}

function setMacMnemonic(mnemonic: string): void {
  const user = process.env.USER ?? "";
  if (!user) throw new Error("USER is not set");
  run("security", [
    "add-generic-password",
    "-a",
    user,
    "-s",
    MNEMONIC_NAME,
    "-w",
    mnemonic,
    "-U",
  ]);
}

function runPowerShell(command: string): string {
  return run("powershell", [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    command,
  ]);
}

function psSingleQuoteEscape(value: string): string {
  return value.replace(/'/g, "''");
}

function getWindowsMnemonic(): string {
  const script = `$c = Get-StoredCredential -Target '${MNEMONIC_NAME}'; if (-not $c) { throw 'Credential not found' }; $c.Password`;
  return runPowerShell(script);
}

function setWindowsMnemonic(mnemonic: string): void {
  const escapedMnemonic = psSingleQuoteEscape(mnemonic);
  const script =
    `if (-not (Get-Module -ListAvailable -Name CredentialManager)) { ` +
    `throw 'Install CredentialManager module first: Install-Module CredentialManager -Scope CurrentUser' }; ` +
    `New-StoredCredential -Target '${MNEMONIC_NAME}' -UserName '$env:USERNAME' -Password '${escapedMnemonic}' -Persist LocalMachine -Type Generic | Out-Null`;
  runPowerShell(script);
}

function getMnemonicForPlatform(): string {
  if (process.platform === "darwin") return getMacMnemonic();
  if (process.platform === "win32") return getWindowsMnemonic();
  throw new Error(`Unsupported platform: ${process.platform}`);
}

function setMnemonicForPlatform(mnemonic: string): void {
  if (process.platform === "darwin") {
    setMacMnemonic(mnemonic);
    return;
  }
  if (process.platform === "win32") {
    setWindowsMnemonic(mnemonic);
    return;
  }
  throw new Error(`Unsupported platform: ${process.platform}`);
}

export const macWinSigner: RawEd25519Signer = async (data: Uint8Array): Promise<Uint8Array> => {
  const mnemonic = getMnemonicForPlatform();
  console.debug("Retrieved mnemonic:", mnemonic);
  const seed = seedFromMnemonic(mnemonic);
  const { rawEd25519Signer } = nobleEd25519Generator(seed);

  const sig = await rawEd25519Signer(data);
  seed.fill(0);

  return sig;
};

// Demo
const seed = crypto.getRandomValues(new Uint8Array(32));
const mnemonic = mnemonicFromSeed(seed);
const acct = nobleEd25519Generator(seed);

setMnemonicForPlatform(mnemonic);

const data = new Uint8Array([1, 2, 3]);
const sig = await macWinSigner(data);
const isValid = await nobleEd25519Verifier(sig, data, acct.ed25519Pubkey);

if (!isValid) {
  console.error("Signature verification failed");
  process.exit(1);
}

console.log("Signature valid?", isValid);
