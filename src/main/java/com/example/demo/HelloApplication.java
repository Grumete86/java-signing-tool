package com.example.demo;

import com.github.jsonldjava.utils.JsonUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Key;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Map;
import javax.swing.JComboBox;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import net.minidev.json.JSONObject;
import java.security.UnrecoverableKeyException;


public class HelloApplication {

    private JFrame frame;
    private JTextArea textArea;
    private JTextArea inputJsonTextArea;
    private JTextField verificationMethodField;
    private JTextArea privateKeyTextArea;
    private JButton signButton;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new HelloApplication().createAndShowGUI());
    }

    private void createAndShowGUI() {
        String verMeth = "did:web:arlabdevelopment.es";
        String jsonExample = "{\n" +
                "    \"@context\": [\n" +
                "        \"https://www.w3.org/2018/credentials/v1\",\n" +
                "        \"https://w3id.org/security/suites/jws-2020/v1\",\n" +
                "        \"https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#\"\n" +
                "    ],\n" +
                "    \"type\": [\n" +
                "        \"VerifiableCredential\"\n" +
                "    ],\n" +
                "    \"id\": \"https://arlabdevelopments.com/.well-known/ArsysParticipant.json\",\n" +
                "    \"issuer\": \"did:web:arlabdevelopments.com\",\n" +
                "    \"issuanceDate\": \"2023-12-11T09:00:00.000Z\",\n" +
                "    \"credentialSubject\": {\n" +
                "        \"gx:legalName\": \"Arsys Internet, S.L.U.\",\n" +
                "        \"gx:headquarterAddress\": {\n" +
                "            \"gx:countrySubdivisionCode\": \"ES-RI\"\n" +
                "        },\n" +
                "        \"gx:legalRegistrationNumber\": {\n" +
                "            \"id\": \"https://arlabdevelopments.com/.well-known/legalRegistrationNumberVC.json\"\n" +
                "        },\n" +
                "        \"gx:legalAddress\": {\n" +
                "            \"gx:countrySubdivisionCode\": \"ES-RI\"\n" +
                "        },\n" +
                "        \"type\": \"gx:LegalParticipant\",\n" +
                "        \"gx-terms-and-conditions:gaiaxTermsAndConditions\": \"70c1d713215f95191a11d38fe2341faed27d19e083917bc8732ca4fea4976700\",\n" +
                "        \"id\": \"https://arlabdevelopments.com/.well-known/ArsysParticipant.json\"\n" +
                "    }\n" +
                "}";

        frame = new JFrame("Certificado");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(800, 600);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.NORTHWEST;
        constraints.insets = new Insets(5, 5, 5, 5);

        JButton buttonObtener = new JButton("Obtener Clave Privada");
        JButton buttonCargar = new JButton("Cargar Certificado");
        inputJsonTextArea = new JTextArea(10, 40);
        inputJsonTextArea.setText(jsonExample);
        privateKeyTextArea = new JTextArea(10, 40);
        verificationMethodField = new JTextField(40);
        verificationMethodField.setText(verMeth);
        signButton = new JButton("Firmar JSON");
        textArea = new JTextArea(10, 40);

        JScrollPane jsonScrollPane = new JScrollPane(inputJsonTextArea);
        JScrollPane privateKeyScrollPane = new JScrollPane(privateKeyTextArea);
        JScrollPane outputScrollPane = new JScrollPane(textArea);

        inputJsonTextArea.setWrapStyleWord(true);
        inputJsonTextArea.setLineWrap(true);
        privateKeyTextArea.setWrapStyleWord(true);
        privateKeyTextArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setLineWrap(true);

        // Configuración de los componentes en el panel principal
        constraints.gridx = 0;
        constraints.gridy = 0;
        mainPanel.add(buttonObtener, constraints);

        constraints.gridy++;
        mainPanel.add(buttonCargar, constraints);

        constraints.gridy++;
        mainPanel.add(new JLabel("JSON a firmar:"), constraints);

        constraints.gridy++;
        constraints.weightx = 1.0;
        constraints.weighty = 1.0;
        constraints.fill = GridBagConstraints.BOTH;
        mainPanel.add(jsonScrollPane, constraints);

        constraints.gridy++;
        constraints.weightx = 0.0;
        constraints.weighty = 0.0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        mainPanel.add(new JLabel("Método de Verificación:"), constraints);

        constraints.gridy++;
        mainPanel.add(verificationMethodField, constraints);

        constraints.gridy++;
        mainPanel.add(new JLabel("Clave Privada (Formato PKCS#8):"), constraints);

        constraints.gridy++;
        constraints.weightx = 1.0;
        constraints.weighty = 1.0;
        constraints.fill = GridBagConstraints.BOTH;
        mainPanel.add(privateKeyScrollPane, constraints);

        constraints.gridy++;
        constraints.weightx = 0.0;
        constraints.weighty = 0.0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        mainPanel.add(signButton, constraints);

        constraints.gridy++;
        constraints.weightx = 1.0;
        constraints.weighty = 2.0;
        constraints.fill = GridBagConstraints.BOTH;
        mainPanel.add(outputScrollPane, constraints);

        buttonObtener.addActionListener(this::obtenerClavePrivada);
        buttonCargar.addActionListener(this::cargarCertificado);
        signButton.addActionListener(this::signJson);

        frame.add(mainPanel);
        frame.setVisible(true);
    }






    private void obtenerClavePrivada(ActionEvent e) {
        try {
            KeyStore keyStore = getKeyStore();
            keyStore.load(null, null); // Cargar el almacén de claves

            Enumeration<String> aliases = keyStore.aliases();
            if (!aliases.hasMoreElements()) {
                privateKeyTextArea.setText("No hay certificados disponibles en el almacén.");
                return;
            }

            // Permitir al usuario elegir un certificado
            JComboBox<String> combo = new JComboBox<>();
            while (aliases.hasMoreElements()) {
                combo.addItem(aliases.nextElement());
            }
            int action = JOptionPane.showConfirmDialog(frame, combo, "Selecciona un certificado", JOptionPane.OK_CANCEL_OPTION);
            if (action != JOptionPane.OK_OPTION) {
                privateKeyTextArea.setText("Selección de certificado cancelada.");
                return;
            }

            String selectedAlias = (String) combo.getSelectedItem();
            Key key = null;

            try {
                key = keyStore.getKey(selectedAlias, null);
            } catch (UnrecoverableKeyException ex) {
                JPasswordField pwd = new JPasswordField(10);
                action = JOptionPane.showConfirmDialog(null, pwd, "Ingresa la contraseña del certificado", JOptionPane.OK_CANCEL_OPTION);
                if (action != JOptionPane.OK_OPTION) {
                    privateKeyTextArea.setText("Carga de certificado cancelada.");
                    return;
                }
                key = keyStore.getKey(selectedAlias, pwd.getPassword());
            }

            if (key == null) {
                privateKeyTextArea.setText("No se pudo recuperar la clave privada para el certificado seleccionado.");
                return;
            }

            if (key instanceof PrivateKey) {
                byte[] encoded = key.getEncoded();
                String privateKeyString = Base64.getEncoder().encodeToString(encoded);
                privateKeyTextArea.setText(privateKeyString);
            } else {
                privateKeyTextArea.setText("No se encontró una clave privada para el certificado seleccionado.");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            privateKeyTextArea.setText("Error al obtener la clave privada: " + ex.getMessage());
        }
    }


    private KeyStore getKeyStore() throws Exception {
        String osName = System.getProperty("os.name").toLowerCase();
        if (osName.contains("win")) {
            return KeyStore.getInstance("Windows-MY");
        } else if (osName.contains("mac")) {
            return KeyStore.getInstance("KeychainStore");
        } else {
            // Para sistemas basados en Unix/Linux, aquí se usa JKS como ejemplo
            return KeyStore.getInstance("JKS");
        }
    }

    private void cargarCertificado(ActionEvent e) {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(frame);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            cargarCertificadoDesdeArchivo(fileChooser.getSelectedFile());
        }
    }

    private void cargarCertificadoDesdeArchivo(File file) {
        JPasswordField pwd = new JPasswordField(10);
        int action = JOptionPane.showConfirmDialog(frame, pwd, "Ingresa la contraseña del certificado", JOptionPane.OK_CANCEL_OPTION);
        if (action != JOptionPane.OK_OPTION) {
            privateKeyTextArea.setText("Carga de certificado cancelada.");
            return;
        }

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream is = new FileInputStream(file)) {
                keyStore.load(is, pwd.getPassword());
            }

            String alias = keyStore.aliases().nextElement();
            Key key = keyStore.getKey(alias, pwd.getPassword());
            if (key instanceof PrivateKey) {
                // Convertir a formato PKCS#8
                byte[] encoded = key.getEncoded();
                String privateKeyString = Base64.getEncoder().encodeToString(encoded);

                privateKeyTextArea.setText("" + privateKeyString);
            } else {
                privateKeyTextArea.setText("No se encontró una clave privada en el certificado.");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            privateKeyTextArea.setText("Error al cargar el certificado: " + ex.getMessage());
        }
    }

    private void signJson(ActionEvent e) {
        String jsonInput = inputJsonTextArea.getText();
        String verificationMethod = verificationMethodField.getText();
        String privateKeyPem = privateKeyTextArea.getText();

        try {
            // Convertir JSON input a Map
            Map<String, Object> jsonDocument = (Map<String, Object>) JsonUtils.fromString(jsonInput);
            JSONObject jsonObject = new JSONObject(jsonDocument);

            // Crear instancia de JSONSigner y firmar el documento
            JSONSigner signer = new JSONSigner();
            JSONObject signedDocument = signer.signDocument(privateKeyPem, jsonObject, verificationMethod);

            // Mostrar el resultado
            textArea.setText(JsonUtils.toPrettyString(signedDocument));
        } catch (Exception ex) {
            ex.printStackTrace();
            textArea.setText("Error al firmar el JSON: " + ex.getMessage());
        }
    }
}