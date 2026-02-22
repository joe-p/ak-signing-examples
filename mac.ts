import { execFileSync } from "child_process";

function run(cmd: string, args: string[]): string {
  return execFileSync(cmd, args, { encoding: "utf-8" }).trim();
}

export function getMacMnemonic(name: string): string {
  const user = process.env.USER ?? "";
  if (!user) throw new Error("USER is not set");
  return run("security", ["find-generic-password", "-a", user, "-s", name, "-w"]);
}

export function setMacMnemonic(name: string, mnemonic: string): void {
  const user = process.env.USER ?? "";
  if (!user) throw new Error("USER is not set");
  run("security", ["add-generic-password", "-a", user, "-s", name, "-w", mnemonic, "-U"]);
}
