import { execFileSync } from "child_process";

function run(cmd: string, args: string[], input?: string): string {
  return execFileSync(cmd, args, { encoding: "utf-8", input }).trim();
}

export function getLinuxMnemonic(name: string): string {
  return run("secret-tool", ["lookup", "service", "algorand", "account", name]);
}

export function setLinuxMnemonic(name: string, mnemonic: string): void {
  run("secret-tool", ["store", "--label", `Algorand mnemonic (${name})`, "service", "algorand", "account", name], `${mnemonic}\n`);
}
