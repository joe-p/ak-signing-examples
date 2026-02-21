import { mnemonicFromSeed, seedFromMnemonic } from "@algorandfoundation/algokit-utils/algo25";
import { nobleEd25519Generator, nobleEd25519Verifier, RawEd25519Signer } from "@algorandfoundation/algokit-utils/crypto";
import { execSync } from "child_process";

const MNEMONIC_NAME = "algorand-mainnet-mnemonic";

export const macSigner: RawEd25519Signer = async (data: Uint8Array): Promise<Uint8Array> => {
	const mn = execSync(`security find-generic-password -a "${process.env.USER}" -s "${MNEMONIC_NAME}" -w`, { encoding: "utf-8" }).trim();
	const seed = seedFromMnemonic(mn);
	const { rawEd25519Signer } = nobleEd25519Generator(seed)

	const sig = await rawEd25519Signer(data);
	seed.fill(0);

	return sig
}

const seed = crypto.getRandomValues(new Uint8Array(32));
const mn = mnemonicFromSeed(seed);
const acct = nobleEd25519Generator(seed);

execSync(`security add-generic-password -a "${process.env.USER}" -s "${MNEMONIC_NAME}" -w "${mn}" -U`, { encoding: "utf-8" });

const data = new Uint8Array([1, 2, 3]);
const sig = await macSigner(data);
const isValid = await nobleEd25519Verifier(sig, data, acct.ed25519Pubkey)

console.log("Signature valid?", isValid);
