import { VDocument } from './models/document'

export type VerifiableCredential = {
  credentialSubject: any
  id: string
  issuanceDate: string
  issuer: string
  type: string
  proof?: object
}

export type VerifiablePresentation = VDocument & {
  '@context': string[]
  type: string[]
  verifiableCredential: any[]
}

export type Example = {
  summary: string
  value: {
    verifiableCredential: VerifiableCredential[]
  }
  credentialSubject: any
  vcTemplate: VerifiableCredential
  vcTemplateFilled: VerifiableCredential
  vpTemplate: object
}

export type ExampleTuple = {
  shape: string
  example: Example
}

export type GaiaXDeploymentPath = 'v1' | 'main' | 'development'

export type ComplianceFormat = CredentialFormats

export type CredentialOffersApiResponseData = {
  data: VDocument
  clearingHouse: string
  jwt?: string
  format: CredentialFormats
}

export type EIDHashResponseData = { hash: string; hashFunction: string }

export type EIDJWSResponseData = { jws: string; valid: boolean; status: string }

export type EIDCertchainPostResponseData = { certChain: string }

export type LegalRegistrationNumberType = 'taxID' | 'EUID' | 'EORI' | 'vatID' | 'leiCode'

export enum CredentialFormats {
  JSON = 'application/json',
  VC_JWT = 'application/vc+jwt',
  VP_LD_JWT = 'application/vp+ld+jwt'
}
