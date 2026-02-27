import { algo, AlgorandClient, microAlgo } from "@algorandfoundation/algokit-utils";
import { mnemonicFromSeed, seedFromMnemonic } from "@algorandfoundation/algokit-utils/algo25";
import {
  nobleEd25519Generator,
  nobleEd25519Verifier,
  RawEd25519Signer,
} from "@algorandfoundation/algokit-utils/crypto";
import { generateAddressWithSigners } from "@algorandfoundation/algokit-utils/transact";
import { Entry } from "@napi-rs/keyring";

function getMnemonic(name: string): string {
  const entry = new Entry('algorand', name)
  const mn = entry.getPassword()

  if (!mn) {
    throw new Error(`No mnemonic found in keyring for ${name}`);
  }

  return mn;
}

function setMnemonic(name: string, mnemonic: string): void {
  const entry = new Entry('algorand', name)
  entry.setPassword(mnemonic)
}


const MNEMONIC_NAME = "algorand-mainnet-mnemonic";

export const rawEd25519Signer: RawEd25519Signer = async (data: Uint8Array): Promise<Uint8Array> => {
  const mnemonic = getMnemonic(MNEMONIC_NAME);
  const seed = seedFromMnemonic(mnemonic);
  const { rawEd25519Signer } = nobleEd25519Generator(seed);

  const sig = await rawEd25519Signer(data);
  seed.fill(0);

  return sig;
};


export const getPubkey = (): Uint8Array => {
  const mnemonic = getMnemonic(MNEMONIC_NAME);
  const seed = seedFromMnemonic(mnemonic);
  const { ed25519Pubkey } = nobleEd25519Generator(seed);
  seed.fill(0);

  return ed25519Pubkey;
}


// Demo
const seed = crypto.getRandomValues(new Uint8Array(32));
const mnemonic = mnemonicFromSeed(seed);
const acct = nobleEd25519Generator(seed);

setMnemonic(MNEMONIC_NAME, mnemonic);

const data = new Uint8Array([1, 2, 3]);
const sig = await rawEd25519Signer(data);
const isValid = await nobleEd25519Verifier(sig, data, acct.ed25519Pubkey);

if (!isValid) {
  console.error("Signature verification failed");
  process.exit(1);
}

console.log("Signature valid?", isValid);

const algorandAccount = generateAddressWithSigners({ rawEd25519Signer, ed25519Pubkey: getPubkey() });

const algorand = AlgorandClient.defaultLocalNet();

await algorand.account.ensureFundedFromEnvironment(algorandAccount.addr, algo(1))

// FIXME: No signer found when algorandAccount is sender without explicit signer
// FIXME: Logs show Sending 0 µALGO from [object Object] to [object Object] via transaction UKEP7PS5G7YAX22ECEQZAOFGHKZZOAMJ3SMJ3VC3UYCJVTRQIN4A
const pay = await AlgorandClient.defaultLocalNet().send.payment({
  sender: algorandAccount,
  signer: algorandAccount,
  receiver: algorandAccount,
  amount: microAlgo(0),
})

if (!pay.confirmation.confirmedRound) {
  console.error("Payment failed");
  process.exit(1);
}
