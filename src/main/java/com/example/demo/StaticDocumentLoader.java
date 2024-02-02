package com.example.demo;

import com.github.jsonldjava.core.DocumentLoader;
import com.github.jsonldjava.core.JsonLdError;
import com.github.jsonldjava.core.RemoteDocument;
import com.github.jsonldjava.utils.JsonUtils;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

public class StaticDocumentLoader extends DocumentLoader {
    private static final Map<String, Object> CACHED_CONTEXTS = new HashMap<>();

    static {
        // Cargar contextos almacenados localmente
        CACHED_CONTEXTS.put("https://www.w3.org/2018/credentials/v1", loadJsonResource("/json/credentials_v1_context.json"));
        CACHED_CONTEXTS.put("https://w3id.org/security/suites/jws-2020/v1", loadJsonResource("/json/jws2020_v1_context.json"));
        CACHED_CONTEXTS.put("https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#", loadJsonResource("/json/trustframework_context.json"));
    }

    @Override
    public RemoteDocument loadDocument(String url) throws JsonLdError {
        if (CACHED_CONTEXTS.containsKey(url)) {
            return new RemoteDocument(url, CACHED_CONTEXTS.get(url));
        }
        // Si no está en caché, utiliza el comportamiento por defecto (o implementa la lógica para cargar desde una URL remota)
        return super.loadDocument(url);
    }

    private static Object loadJsonResource(String path) {
        try (InputStream inputStream = StaticDocumentLoader.class.getResourceAsStream(path)) {
            return JsonUtils.fromInputStream(inputStream);
        } catch (Exception e) {
            throw new RuntimeException("Error al cargar el contexto JSON-LD desde: " + path, e);
        }
    }
}