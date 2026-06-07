package com.example.authz.config;

import com.example.authz.engine.AuthorizationEngine;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** Loads + compiles authorization.yaml (fail-fast). */
public final class YamlLoader {
    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());

    private YamlLoader() {}

    @SuppressWarnings("unchecked")
    public static AuthorizationEngine load(String yamlText) {
        yamlText = yamlText.replaceAll("\\*(?=\\s*[,\\]])", "\"*\"");
        Map<String, Object> root;
        try {
            root = YAML.readValue(yamlText, Map.class);
        } catch (IOException e) {
            throw new ConfigException("authorization.yaml is not valid YAML: " + e.getMessage());
        }
        if (root == null || !(root.get("rules") instanceof List<?> rules)) {
            throw new ConfigException("authorization.yaml must contain a 'rules' list");
        }
        return AuthorizationEngine.compile((List<Map<String, Object>>) rules);
    }

    public static AuthorizationEngine loadFile(Path path) {
        try {
            return load(Files.readString(path));
        } catch (IOException e) {
            throw new ConfigException("cannot read " + path + ": " + e.getMessage());
        }
    }
}
