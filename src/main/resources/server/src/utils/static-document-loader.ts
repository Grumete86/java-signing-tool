import { RemoteDocument, JsonLd, Url } from 'jsonld/jsonld-spec'
import vcCtx from '../public/credentials_v1_context.json'
import jwsCtx from '../public/jws2020_v1_context.json'
import trustframeworkCtx from '../public/trustframework_context.json'

const CACHED_CONTEXTS: { [url: string]: JsonLd } = {
  'https://www.w3.org/2018/credentials/v1': vcCtx as any,
  'https://w3id.org/security/suites/jws-2020/v1': jwsCtx as any,
  'https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#': trustframeworkCtx
}

export const staticDocumentLoader: (url: Url) => Promise<RemoteDocument> = async url => {
  if (url in CACHED_CONTEXTS) {
    return {
      contextUrl: undefined,
      document: CACHED_CONTEXTS[url],
      documentUrl: url
    }
  }
  const document = await (await fetch(url)).json()
  return {
    contextUrl: undefined,
    document,
    documentUrl: url
  }
}
