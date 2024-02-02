import { VDocument } from './models/document'
import { CompactSign, importPKCS8 } from 'jose'
import { canonize, JsonLdDocument } from 'jsonld'
import { staticDocumentLoader } from './utils/static-document-loader'


async function normalize(payload: JsonLdDocument) {
    // Convert to RDF 
    return await canonize(payload, {
        algorithm: 'URDNA2015',
        format: 'application/n-quads',
        documentLoader: staticDocumentLoader
    })
}

function hash(payload: string) {
    return computePayloadHash(payload)
}

async function computePayloadHash(payload: string) {
    // Encode the payload
    const encoder = new TextEncoder()
    const data = encoder.encode(payload)
    // Hashing the payload
    const digestBuffer = await crypto.subtle.digest('SHA-256', data)
    const digestArray = new Uint8Array(digestBuffer)
    // Turning Hex string
    return Array.from(digestArray)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
}


export const sign = async (pemPrivateKey: string, verifiableCredential: any, verificationMethod: string): Promise<VDocument> => {
    // Step 1: Import key from the PEM format
    const rsaPrivateKey = await importPKCS8(pemPrivateKey, 'PS256')

    // Step 2: Compute the hash of the normalized verifiable credential
    const credentialNormalized = await normalize(verifiableCredential)
    const credentialHashed = await hash(credentialNormalized)
    const credentialEncoded = new TextEncoder().encode(credentialHashed)

    // Step 3: Sign
    const credentialJws = await new CompactSign(credentialEncoded).setProtectedHeader({ alg: 'PS256', b64: false, crit: ['b64'] }).sign(rsaPrivateKey)

    // Step 4: Add the signature to the verifiable credential
    return {
        ...verifiableCredential,
        proof: {
            type: 'JsonWebSignature2020',
            created: new Date().toISOString(),
            proofPurpose: 'assertionMethod',
            verificationMethod: verificationMethod,
            jws: credentialJws
        }
    }
}
