# Using Mainnet Secrets

## Using Secrets From a Local Machine

If you are using a mainnet account via secrets on a local machine it is recommended to store the secret material in your OS keychain and only load the secret material when signing. **Writing secret material in plaintext to your environment (i.e. in a .env) is not recommended.** Doing so may lead to accidental leakage through commits. It will also keep the secret in memory throughout the entirety of program execution, which may give a malicious program or dependency the ability to extract secret material.

### MacOS Keyring

To add a mnemonic to your keychain:

```bash
security add-generic-password \
  -a "$USER" \
  -s "algorand-mainnet-mnemonic" \
  -w "your 25 word mnemonic goes here" \
  -U
```

Then to load it programmatically

```ts
function run(cmd: string, args: string[]): string {
  return execFileSync(cmd, args, { encoding: "utf-8" }).trim();
}

export function getMacMnemonic(name: string): string {
  const user = process.env.USER ?? "";
  if (!user) throw new Error("USER is not set");
  return run("security", ["find-generic-password", "-a", user, "-s", name, "-w"]);
}
```

And turn it into a Algorand address with all signing functions:

```ts
const MNEMONIC_NAME = "algorand-mainnet-mnemonic";

export const rawEd25519Signer: RawEd25519Signer = async (data: Uint8Array): Promise<Uint8Array> => {
  const mnemonic = getMacMnemonic(MNEMONIC_NAME);
  const seed = seedFromMnemonic(mnemonic);
  const { rawEd25519Signer } = nobleEd25519Generator(seed);

  const sig = await rawEd25519Signer(data);
  seed.fill(0);

  return sig;
};

export const getPubkey = (): Uint8Array => {
  const mnemonic = getMacMnemonic(MNEMONIC_NAME);
  const seed = seedFromMnemonic(mnemonic);
  const { ed25519Pubkey } = nobleEd25519Generator(seed);
  seed.fill(0);

  return ed25519Pubkey;
}

const addrWithSigners = generateAddressWithSigners({ rawEd25519Signer, ed25519Pubkey: getPubkey() });
```

### Windows Keyring

First, you may need to install [CredentialManager](https://www.powershellgallery.com/packages/CredentialManager/2.0):

```powershell
Install-Module -Name CredentialManager
```

Then, to add a mnemonic to your keychain:

```powershell
New-StoredCredential -Target 'algorand-mainnet-mnemonic' -UserName $env:USERNAME -Password 'your 25 word mnemonic goes here' -Persist LocalMachine -Type Generic | Out-Null
```

Then to load it programmatically:

```ts
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
```

And finally turn it into an Algorand address with all signing functions:

```ts
export const rawEd25519Signer: RawEd25519Signer = async (data: Uint8Array): Promise<Uint8Array> => {
  const mnemonic = getWindowsMnemonic(MNEMONIC_NAME);
  const seed = seedFromMnemonic(mnemonic);
  const { rawEd25519Signer } = nobleEd25519Generator(seed);

  const sig = await rawEd25519Signer(data);
  seed.fill(0);

  return sig;
};

export const getPubkey = (): Uint8Array => {
  const mnemonic = getWindowsMnemonic(MNEMONIC_NAME);
  const seed = seedFromMnemonic(mnemonic);
  const { ed25519Pubkey } = nobleEd25519Generator(seed);
  seed.fill(0);

  return ed25519Pubkey;
}

const addrWithSigners = generateAddressWithSigners({ rawEd25519Signer, ed25519Pubkey: getPubkey() });
```

### Linux Keyring

NOTE: This assumes you have secret-tool installed with a compatible keyring, such as GNOME keyring or KWallet. Various distributions might have different tools available.

To add your mnemonic to the keychain:

```sh
"your 25 word mnemonic goes here" | secret-tool store --label "Algorand mnemonic (mainnet)" service algorand account mainnet-mnemonic
```

Then to load it programmatically:

```ts
function run(cmd: string, args: string[], input?: string): string {
  return execFileSync(cmd, args, { encoding: "utf-8", input }).trim();
}

export function getLinuxMnemonic(name: string): string {
  return run("secret-tool", ["lookup", "service", "algorand", "account", name]);
}
```

And finally turn it into an Algorand address with all signing functions:

```ts
export const rawEd25519Signer: RawEd25519Signer = async (data: Uint8Array): Promise<Uint8Array> => {
  const mnemonic = getLinuxMnemonic(MNEMONIC_NAME);
  const seed = seedFromMnemonic(mnemonic);
  const { rawEd25519Signer } = nobleEd25519Generator(seed);

  const sig = await rawEd25519Signer(data);
  seed.fill(0);

  return sig;
};

export const getPubkey = (): Uint8Array => {
  const mnemonic = getLinuxMnemonic(MNEMONIC_NAME);
  const seed = seedFromMnemonic(mnemonic);
  const { ed25519Pubkey } = nobleEd25519Generator(seed);
  seed.fill(0);

  return ed25519Pubkey;
}

const addrWithSigners = generateAddressWithSigners({ rawEd25519Signer, ed25519Pubkey: getPubkey() });
```

## Secrets From CI

### KMS with OIDC

The best practice for performing signing operations in CI is to use an external KMS and authenticate with OIDC. For guides for setting up OIDC, refer to the [GitHub documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments).

Using the KMS, you can retrieve the public key and implement `RawEd25519Signer` signer which can then be used to generate an Algorand address and all Algorand-specific signing functions. For example, with AWS:

```ts
const kms = new KMSClient({ region: process.env.AWS_REGION });

const rawEd25519Signer: RawEd25519Signer = async (data: Uint8Array): Promise<Uint8Array> => {
  const resp = await kms.send(
    new SignCommand({
      KeyId: process.env.KEY_ID,
      Message: data,
      MessageType: "RAW",
      SigningAlgorithm: "ED25519_SHA_512",
    })
  );

  if (!resp.Signature) {
    throw new Error("No signature returned from KMS");
  }

  return resp.Signature;
}

const pubkeyResp = await kms.send(new GetPublicKeyCommand({
  KeyId: process.env.KEY_ID,
}));

if (!pubkeyResp.PublicKey) {
  throw new Error("No public key returned from KMS");
}

const spki = Buffer.from(pubkeyResp.PublicKey as Uint8Array);


const ed25519SpkiPrefix = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
]);

if (!spki.subarray(0, 12).equals(ed25519SpkiPrefix)) {
  throw new Error("Unexpected public key format");
}

const ed25519Pubkey = spki.subarray(12); // 32 bytes

const addrWithSigner = generateAddressWithSigners({ rawEd25519Signer, ed25519Pubkey });
```

# Sharing Secrets and Multisig

It's common for a application to have multiple developers that can deploy changes to mainnet. It may be tempting to share a secret for a single account (manually or through a secrets manager), but this is **not recommended**. Instead, it is recommended to setup a multisig account between all the developers. The multisig account can be a 1/N threshold, which would still allow a single developer to make changes. The benefit of a multisig is that secrets do not need to be shared and all actions are immutably auditable on-chain. Each developer should then follow the practices outlined above.

```ts
const addrWithSigners = generateAddressWithSigners({ rawEd25519Signer: signer, ed25519Pubkey: pubkey });
const msigData: MultisigMetadata = {
  version: 1,
  threshold: 1,
  addrs: [
    otherSigner, // Address of the other signer
    addrWithSigners.addr
  ],
}

const algorand = AlgorandClient.defaultLocalNet();

// Create a multisig account that can be used to sign as a 1/N signer
const msigAccount = new MultisigAccount(msigData, [addrWithSigners])

// Send a transaction using the multisig account
const pay = algorand.send.payment({
  sender: msigAccount,
  amount: microAlgos(0),
  receiver: otherSigner,
}) 
```

# Key Rotation

Algorand has native support for key rotation through a feature called rekeying. Rekeying allows the blockchain address to stay the same while allowing for rotation of the underlying keypair. For example, a common pattern is to have an admin address that can deploy changes to a production contract. Rekeying allows the admin address to remain constant in the contract but allow the secrets used to authorize transactions to rotate. Rekeying can be done with any transaction type, but the simplest is to do a 0 ALGO payment to oneself with the rekeyTo field set.

```ts
const originalAddrWithSigners = generateAddressWithSigners({ rawEd25519Signer: originalSigner, ed25519Pubkey: originalPubkey });

const newAddrWithSigners = generateAddressWithSigners({
  rawEd25519Signer: newSigner,
  ed25519Pubkey: newPubkey,
  // NOTE: We are specifying sendingAddress so we can properly sign transactions on behalf of the original address
  sendingAddress: originalAddrWithSigners.addr,
});


const algorand = AlgorandClient.defaultLocalNet();

algorand.send.payment({
  sender: originalAddrWithSigners,
  amount: microAlgos(0),
  receiver: originalAddrWithSigners,
  rekeyTo: newAddrWithSigners,
}) 
```
