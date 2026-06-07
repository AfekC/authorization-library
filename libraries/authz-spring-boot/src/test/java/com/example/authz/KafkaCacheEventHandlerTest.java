package com.example.authz;

import com.example.authz.sync.KafkaCacheEventHandler;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class KafkaCacheEventHandlerTest {

    private static Object getField(Object obj, String name) throws Exception {
        Field field = KafkaCacheEventHandler.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(obj);
    }

    @Test
    void constructor_usesDefaultsWhenNull() throws Exception {
        KafkaCacheEventHandler handler = new KafkaCacheEventHandler(
                List.of("localhost:9092"), null, null, null, null, null);
        assertEquals("role-updates", getField(handler, "updatesTopic"));
        assertEquals("role-delete", getField(handler, "deleteTopic"));
        assertEquals("publish-roles", getField(handler, "publishTopic"));
        assertEquals("authz-cache-sync", getField(handler, "groupId"));
        assertEquals("authz-cache-sync", getField(handler, "clientId"));
    }

    @Test
    void constructor_usesProvidedValues() throws Exception {
        KafkaCacheEventHandler handler = new KafkaCacheEventHandler(
                List.of("broker:9092"), "my-updates", "my-deletes",
                "my-publish", "my-group", "my-client");
        assertEquals("my-updates", getField(handler, "updatesTopic"));
        assertEquals("my-deletes", getField(handler, "deleteTopic"));
        assertEquals("my-publish", getField(handler, "publishTopic"));
        assertEquals("my-group", getField(handler, "groupId"));
        assertEquals("my-client", getField(handler, "clientId"));
    }

    @Test
    void parse_returnsNullForNullInput() {
        KafkaCacheEventHandler handler = new KafkaCacheEventHandler(
                List.of("localhost:9092"), null, null, null, null, null);
        assertNull(handler.parse(null));
    }

    @Test
    void parse_returnsNullForInvalidJson() {
        KafkaCacheEventHandler handler = new KafkaCacheEventHandler(
                List.of("localhost:9092"), null, null, null, null, null);
        assertNull(handler.parse("not json"));
    }

    @Test
    void parse_returnsMapForValidJson() {
        KafkaCacheEventHandler handler = new KafkaCacheEventHandler(
                List.of("localhost:9092"), null, null, null, null, null);
        Map<String, Object> result = handler.parse("{\"roleId\":\"admin\",\"permissions\":[\"*\"]}");
        assertNotNull(result);
        assertEquals("admin", result.get("roleId"));
    }
}
