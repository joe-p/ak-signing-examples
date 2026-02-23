import { AlgorandClient, microAlgos } from "@algorandfoundation/algokit-utils";
import { RawEd25519Signer } from "@algorandfoundation/algokit-utils/crypto";
import { generateAddressWithSigners } from "@algorandfoundation/algokit-utils/transact";
import { KMSClient, SignCommand, GetPublicKeyCommand } from "@aws-sdk/client-kms";

// The following environment variables must be set for this to work:
// - AWS_REGION
// - KEY_ID
// - AWS_ACCESS_KEY_ID
// - AWS_SECRET_ACCESS_KEY
const kms = new KMSClient({ region: process.env.AWS_REGION });

const originalSigner: RawEd25519Signer = async (data: Uint8Array): Promise<Uint8Array> => {
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

const addrWithSigner = generateAddressWithSigners({ rawEd25519Signer: originalSigner, ed25519Pubkey });

const algorand = AlgorandClient.defaultLocalNet();

await algorand.account.ensureFundedFromEnvironment(addrWithSigner.addr, microAlgos(1e6));

const pay = await algorand.send.payment({
  sender: addrWithSigner,
  signer: addrWithSigner,
  amount: microAlgos(0),
  receiver: addrWithSigner,
})

console.debug(pay.confirmation)
