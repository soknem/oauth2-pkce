package com.oauth.authorization_server.service;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.oauth.authorization_server.domain.Role;
import com.oauth.authorization_server.domain.User;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.Set;

@Slf4j
public class CustomUserDetailsDeserializer extends JsonDeserializer<CustomUserDetails> {

    private static final TypeReference<Set<Role>> SIMPLE_GRANTED_AUTHORITY_LIST = new TypeReference<>() {
    };

    @Override
    public CustomUserDetails deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

        ObjectMapper mapper = (ObjectMapper) p.getCodec();
        JsonNode jsonNode = mapper.readTree(p);

        JsonNode userJsonNode = readJsonNode(jsonNode, "user");

        Set<Role> userAuthorities = mapper.convertValue(
                jsonNode.get("userAuthorities"),
                SIMPLE_GRANTED_AUTHORITY_LIST
        );

        log.info("Authorities: {}", userAuthorities);

        Long id = readJsonNode(userJsonNode, "id").asLong();
        String email = readJsonNode(userJsonNode, "email").asText();
        String password = readJsonNode(userJsonNode, "password").asText();
        boolean isEnabled = readJsonNode(userJsonNode, "isEnabled").asBoolean();
        String dob = readJsonNode(userJsonNode, "dob").asText();
        User user = new User();
        user.setId(id);
        user.setEmail(email);
        user.setPassword(password);
        log.info("DOB: {}", dob);
        user.setIsEnabled(isEnabled);

        CustomUserDetails customUserDetails = new CustomUserDetails();
        customUserDetails.setUser(user);

        return customUserDetails;
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }

}
