"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const sign_1 = require("./src/sign");
const PORT = process.env.PORT || 5432;
const app = (0, express_1.default)();
// parse application/x-www-form-urlencoded
app.use(body_parser_1.default.urlencoded({ extended: false }));
// parse application/json
app.use(body_parser_1.default.json());
app.post("/", (request, response) => {
    const json_credential = JSON.parse(request.body.credential);
    const stringKey = request.body.key;
    const verificationMethod = request.body.verification_method;
    const signedCredential = (0, sign_1.sign)(stringKey, json_credential, verificationMethod);
    signedCredential
        .then(cred => JSON.stringify(cred))
        .then(json => response.send(json));
});
app.listen(PORT, () => {
    console.log("Server Listening on PORT:", PORT);
});
// async function normalize(payload: JsonLdDocument) {
//     return await canonize(payload, {
//         algorithm: 'URDNA2015',
//         format: 'application/n-quads',
//         documentLoader: staticDocumentLoader
//     })
// }
// function hash(payload: string) {
//     return computePayloadHash(payload)
// }
// async function computePayloadHash(payload: string) {
//     const encoder = new TextEncoder()
//     const data = encoder.encode(payload)
//     const digestBuffer = await crypto.subtle.digest('SHA-256', data)
//     const digestArray = new Uint8Array(digestBuffer)
//     return Array.from(digestArray)
//         .map(b => b.toString(16).padStart(2, '0'))
//         .join('')
// }
// const signVerifiableCredential = async (pemPrivateKey: string, verifiableCredential: any, verificationMethod: string): Promise<VDocument> => {
//     // Step 1: Import key from the PEM format
//     const rsaPrivateKey = await importPKCS8(pemPrivateKey, 'PS256')
//     // Step 2: Compute the hash of the normalized verifiable credential
//     const credentialNormalized = await normalize(verifiableCredential)
//     const credentialHashed = await hash(credentialNormalized)
//     const credentialEncoded = new TextEncoder().encode(credentialHashed)
//     // Step 3: Sign
//     const credentialJws = await new CompactSign(credentialEncoded).setProtectedHeader({ alg: 'PS256', b64: false, crit: ['b64'] }).sign(rsaPrivateKey)
//     // Step 4: Add the signature to the verifiable credential
//     return {
//         ...verifiableCredential,
//         proof: {
//             type: 'JsonWebSignature2020',
//             created: new Date().toISOString(),
//             proofPurpose: 'assertionMethod',
//             verificationMethod: verificationMethod,
//             jws: credentialJws
//         }
//     }
// }
