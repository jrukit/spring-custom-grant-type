package com.oauth2.custom_grant_type;

import jakarta.annotation.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

public class CustomGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    /**
     * Sub-class constructor.
     *
     * @param authorizationGrantType the authorization grant type
     * @param clientPrincipal        the authenticated client principal
     * @param additionalParameters   the additional parameters
     */
    public CustomGrantAuthenticationToken(Authentication clientPrincipal, @Nullable Map<String, Object> additionalParameters) {
        super(new AuthorizationGrantType("custom"), clientPrincipal, additionalParameters);
    }
}
