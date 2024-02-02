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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.staticDocumentLoader = void 0;
const credentials_v1_context_json_1 = __importDefault(require("../public/credentials_v1_context.json"));
const jws2020_v1_context_json_1 = __importDefault(require("../public/jws2020_v1_context.json"));
const trustframework_context_json_1 = __importDefault(require("../public/trustframework_context.json"));
const CACHED_CONTEXTS = {
    'https://www.w3.org/2018/credentials/v1': credentials_v1_context_json_1.default,
    'https://w3id.org/security/suites/jws-2020/v1': jws2020_v1_context_json_1.default,
    'https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#': trustframework_context_json_1.default
};
const staticDocumentLoader = (url) => __awaiter(void 0, void 0, void 0, function* () {
    if (url in CACHED_CONTEXTS) {
        return {
            contextUrl: undefined,
            document: CACHED_CONTEXTS[url],
            documentUrl: url
        };
    }
    const document = yield (yield fetch(url)).json();
    return {
        contextUrl: undefined,
        document,
        documentUrl: url
    };
});
exports.staticDocumentLoader = staticDocumentLoader;
