"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sign = void 0;
const jose_1 = require("jose");
const jsonld_1 = require("jsonld");
const static_document_loader_1 = require("./utils/static-document-loader");
function normalize(payload) {
    return __awaiter(this, void 0, void 0, function* () {
        return yield (0, jsonld_1.canonize)(payload, {
            algorithm: 'URDNA2015',
            format: 'application/n-quads',
            documentLoader: static_document_loader_1.staticDocumentLoader
        });
    });
}
function hash(payload) {
    return computePayloadHash(payload);
}
function computePayloadHash(payload) {
    return __awaiter(this, void 0, void 0, function* () {
        const encoder = new TextEncoder();
        const data = encoder.encode(payload);
        const digestBuffer = yield crypto.subtle.digest('SHA-256', data);
        const digestArray = new Uint8Array(digestBuffer);
        return Array.from(digestArray)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    });
}
const sign = (pemPrivateKey, verifiableCredential, verificationMethod) => __awaiter(void 0, void 0, void 0, function* () {
    // Step 1: Import key from the PEM format
    const rsaPrivateKey = yield (0, jose_1.importPKCS8)(pemPrivateKey, 'PS256');
    // Step 2: Compute the hash of the normalized verifiable credential
    const credentialNormalized = yield normalize(verifiableCredential);
    const credentialHashed = yield hash(credentialNormalized);
    const credentialEncoded = new TextEncoder().encode(credentialHashed);
    // Step 3: Sign
    const credentialJws = yield new jose_1.CompactSign(credentialEncoded).setProtectedHeader({ alg: 'PS256', b64: false, crit: ['b64'] }).sign(rsaPrivateKey);
    // Step 4: Add the signature to the verifiable credential
    return Object.assign(Object.assign({}, verifiableCredential), { proof: {
            type: 'JsonWebSignature2020',
            created: new Date().toISOString(),
            proofPurpose: 'assertionMethod',
            verificationMethod: verificationMethod,
            jws: credentialJws
        } });
});
exports.sign = sign;
