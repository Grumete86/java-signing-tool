package com.example.demo;

import com.github.jsonldjava.core.JsonLdProcessor;
import com.github.jsonldjava.core.JsonLdOptions;
import com.github.jsonldjava.core.RDFDataset;
import com.github.jsonldjava.utils.JsonUtils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import net.minidev.json.JSONObject;
import java.util.Date;

public class JSONSigner {

    // ... Resto de la clase ...

    private String normalize(Map<String, Object> jsonDocument) throws Exception {
        try{
            JsonLdOptions options = new JsonLdOptions();
            options.setDocumentLoader(new StaticDocumentLoader());

            System.out.println("JSON Document: " + JsonUtils.toPrettyString(jsonDocument));
            // Realizar la normalización del JSON-LD
            RDFDataset dataset = (RDFDataset) JsonLdProcessor.normalize(jsonDocument, options);
            // Serializar el RDFDataset a String
            return JsonUtils.toPrettyString(dataset);
        } catch (Exception e) {
            System.err.println("Error en la inicialización estática: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error en la inicialización estática", e);
        }
    }

    private String computePayloadHash(String payload) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(payload.getBytes());
        return bytesToHex(hash);
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private PrivateKey importPrivateKeyFromPEM(String pemKey) throws Exception {
        // Elimina los encabezados y pies de página de PEM y decodifica la clave
        String privateKeyPEM = pemKey.replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }

    private String signData(byte[] data, PrivateKey privateKey) throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.PS256)
                .base64URLEncodePayload(false)
                .criticalParams(new HashSet<>(Collections.singletonList("b64")))
                .build();

        Payload payload = new Payload(Base64.getUrlEncoder().withoutPadding().encodeToString(data));
        JWSObject jwsObject = new JWSObject(header, payload);

        JWSSigner signer = new RSASSASigner(privateKey);
        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    public JSONObject signDocument(String pemPrivateKey, JSONObject verifiableCredential, String verificationMethod) throws Exception {
        PrivateKey privateKey = importPrivateKeyFromPEM(pemPrivateKey);

        // Normalizar y computar el hash del verifiable credential
        String normalizedCredential = normalize(verifiableCredential);
        String credentialHashed = computePayloadHash(normalizedCredential);

        // Firmar el hash
        String credentialJws = signData(credentialHashed.getBytes(), privateKey);

        // Añadir la firma al verifiable credential
        JSONObject proof = new JSONObject();
        proof.put("type", "JsonWebSignature2020");
        proof.put("created", new Date().toString()); // Formato de fecha adecuado
        proof.put("proofPurpose", "assertionMethod");
        proof.put("verificationMethod", verificationMethod);
        proof.put("jws", credentialJws);

        JSONObject signedCredential = new JSONObject(verifiableCredential);
        signedCredential.put("proof", proof);

        return signedCredential;
    }
    // ... Métodos para importar la clave, firmar los datos, etc. ...
}