import { execFileSync } from "child_process";

function run(cmd: string, args: string[]): string {
  return execFileSync(cmd, args, { encoding: "utf-8" }).trim();
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

export function getWindowsMnemonic(name: string): string {
  const script =
    `$c = Get-StoredCredential -Target '${name}'; ` +
    `if (-not $c) { throw 'Credential not found' }; ` +
    `$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($c.Password); ` +
    `try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } ` +
    `finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }`;
  return runPowerShell(script);
}

export function setWindowsMnemonic(name: string, mnemonic: string): void {
  const script =
    `if (-not (Get-Module -ListAvailable -Name CredentialManager)) { ` +
    `throw 'Install CredentialManager module first: Install-Module CredentialManager -Scope CurrentUser' }; ` +
    `New-StoredCredential -Target '${name}' -UserName $env:USERNAME -Password '${mnemonic}' -Persist LocalMachine -Type Generic | Out-Null`;
  runPowerShell(script);
}
