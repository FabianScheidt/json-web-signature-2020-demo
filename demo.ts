import { CompactSign, importJWK } from "jose";
import { JWK } from "jose/dist/types/types";
import { canonize, JsonLdDocument } from "jsonld";
import * as crypto from "crypto";

/**
 * Utility methods
 */
async function normalize(payload: JsonLdDocument): Promise<string> {
  return canonize(payload, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
  });
}

function sha256(payload: string): Buffer {
  const h = crypto.createHash("sha256");
  h.update(payload);
  return h.digest();
}

// https://www.w3.org/community/reports/credentials/CG-FINAL-lds-jws2020-20220721/#jose-conformance
function getAlg(key: JWK): string {
  if (typeof key !== "object") {
    throw new Error(`Can't determine alg from Uint8Array`);
  }

  const signatures: Record<string, Record<string, string> | string> = {
    OKP: {
      Ed25519: "EdDSA",
    },
    EC: {
      secp256k1: "ES256K",
      "P-256": "ES256",
      "P-384": "ES384",
    },
    RSA: "PS256",
  };

  if (key.kty && key.kty in signatures) {
    const s = signatures[key.kty];
    if (typeof s === "string") {
      return s;
    }
    if (key.crv && key.crv in s) {
      return s[key.crv];
    }
  }

  throw new Error(`Can't determine alg for kty ${key.kty} and crv ${key.crv}`);
}

async function sign(jwk: JWK, payload: Uint8Array): Promise<string> {
  const key = await importJWK(keypair_0.privateKeyJwk);
  return await new CompactSign(payload)
    .setProtectedHeader({ alg: getAlg(jwk), b64: false, crit: ["b64"] })
    .sign(key);
}

/**
 * Test Vectors
 * https://www.w3.org/community/reports/credentials/CG-FINAL-lds-jws2020-20220721/#test-vectors
 */
const keypair_0 = {
  id: "#ovsDKYBjFemIy8DVhc-w2LSi8CvXMw2AYDzHj04yxkc",
  type: "JsonWebKey2020",
  controller: "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
  publicKeyJwk: {
    kty: "OKP",
    crv: "Ed25519",
    x: "CV-aGlld3nVdgnhoZK0D36Wk-9aIMlZjZOK2XhPMnkQ",
  },
  privateKeyJwk: {
    kty: "OKP",
    crv: "Ed25519",
    x: "CV-aGlld3nVdgnhoZK0D36Wk-9aIMlZjZOK2XhPMnkQ",
    d: "m5N7gTItgWz6udWjuqzJsqX-vksUnxJrNjD5OilScBc",
  },
};

const vc_0 = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
    "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
  ],
  id: "http://example.gov/credentials/3732",
  type: ["VerifiableCredential", "UniversityDegreeCredential"],
  issuer: {
    id: "https://example.com/issuer/123",
  },
  issuanceDate: "2020-03-10T04:24:12.164Z",
  credentialSubject: {
    id: "did:example:456",
    degree: {
      type: "BachelorDegree",
      name: "Bachelor of Science and Arts",
    },
  },
  proof: {
    type: "JsonWebSignature2020",
    created: "2019-12-11T03:50:55Z",
    jws: "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..MJ5GwWRMsadCyLNXU_flgJtsS32584MydBxBuygps_cM0sbU3abTEOMyUvmLNcKOwOBE1MfDoB1_YY425W3sAg",
    proofPurpose: "assertionMethod",
    verificationMethod:
      "https://example.com/issuer/123#ovsDKYBjFemIy8DVhc-w2LSi8CvXMw2AYDzHj04yxkc",
  },
};

/**
 * Actual Implementation starts here
 */
async function run() {
  // Normalize Credential
  const credential: Record<string, unknown> = { ...vc_0 };
  delete credential.proof;
  const credentialNormalized = await normalize(credential);

  // Normalize Proof
  const proof: Record<string, unknown> = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    ...vc_0.proof,
  };
  delete proof.jws;
  const proofNormalized = await normalize(proof);

  // Now combine hashes of both!
  const concat = Buffer.concat([
    sha256(proofNormalized),
    sha256(credentialNormalized),
  ]);

  // Sign
  const signed = await sign(keypair_0.privateKeyJwk, concat);

  // Compare result
  console.log("Expected: ", vc_0.proof.jws);
  console.log("Actual:   ", signed);
}
run().then(() => console.log("Done!"));
