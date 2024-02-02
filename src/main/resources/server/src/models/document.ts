import { JsonLdDocument } from 'jsonld'
import { CredentialFormats, VerifiableCredential } from '../sharedTypes'

export type ShapeName = string | string[]

export type VDocument = VerifiableCredential &
  JsonLdDocument & {
    type: ShapeName
    verifiableCredential?: JsonLdDocument[]
    proof?: any
  }

export type StorableVDocument = {
  docName: string
  privateKey?: string
  document: VDocument
  key?: string
  rawDocument?: string
  format?: CredentialFormats
}
