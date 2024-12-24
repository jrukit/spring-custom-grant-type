package com.oauth2.custom_grant_type;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.security.Principal;
import java.util.Collections;
import java.util.Optional;
import java.util.Properties;

public class CustomGrantAuthenticationProvider implements AuthenticationProvider {
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    public CustomGrantAuthenticationProvider(OAuth2AuthorizationService authorizationService,
                                             OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomGrantAuthenticationToken customCodeGrantAuthentication = (CustomGrantAuthenticationToken) authentication;

        // Ensure the client is authenticated
        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(customCodeGrantAuthentication);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        // Ensure the client is configured to use this authorization grant type
        if (!registeredClient.getAuthorizationGrantTypes().contains(customCodeGrantAuthentication.getGrantType())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        String username = (String) ((CustomGrantAuthenticationToken) authentication).getAdditionalParameters().get("username");
        String password = (String) ((CustomGrantAuthenticationToken) authentication).getAdditionalParameters().get("password");
        // LDAP

        try {
            authenticateAndGetRoleName(username, password);
        } catch (NamingException e) {
            throw new RuntimeException(e);
        }

        // Generate the access token
        OAuth2AccessToken accessToken = generateAccessToken(customCodeGrantAuthentication, clientPrincipal, registeredClient);
        // Generate the refresh token
        OAuth2RefreshToken refreshToken = generateRefreshToken(customCodeGrantAuthentication, clientPrincipal, registeredClient);

        // Initialize the OAuth2Authorization and set token configurations
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(clientPrincipal.getName())
                .attribute(Principal.class.getName(), new UsernamePasswordAuthenticationToken(customCodeGrantAuthentication.getName(), null, Collections.emptyList()))
                .authorizationGrantType(customCodeGrantAuthentication.getGrantType());
        authorizationBuilder.accessToken(accessToken);
        authorizationBuilder.refreshToken(refreshToken);
        String id = clientPrincipal.getRegisteredClient().getClientId() + "_" + username;
        authorizationBuilder.id(id);
        OAuth2Authorization authorization = authorizationBuilder.build();

        // Save the OAuth2Authorization
        this.authorizationService.save(authorization);

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken);
    }

    private String[] authenticateAndGetRoleName(String username, String password) throws NamingException {
            Properties ldapEnv = new Properties();
            ldapEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            ldapEnv.put(Context.PROVIDER_URL, "ldap://localhost:389/");
            ldapEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
            String securityPrincipal = "cn=" + username + ",dc=springframework,dc=org";
            ldapEnv.put(Context.SECURITY_PRINCIPAL, securityPrincipal);
            ldapEnv.put(Context.SECURITY_CREDENTIALS, password);
            DirContext ldapContext = initialDirContext(ldapEnv);

            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.ONELEVEL_SCOPE);

            NamingEnumeration<SearchResult> searchResults = ldapContext.search("dc=springframework,dc=org", "(&(objectClass=person))", new String[]{username}, searchControls);

            Optional<SearchResult> result = Collections.list(searchResults).stream().filter(r -> r.getAttributes().get("memberOf") != null).findFirst();

            ldapContext.close();
        return new String[]{"admin"};
    }

    public DirContext initialDirContext(Properties ldapEnv) throws NamingException {
        return new InitialDirContext(ldapEnv);
    }

    private OAuth2AccessToken generateAccessToken(CustomGrantAuthenticationToken customGrantAuthentication, OAuth2ClientAuthenticationToken clientPrincipal, RegisteredClient registeredClient) {
        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(clientPrincipal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(customGrantAuthentication.getGrantType())
                .authorizationGrant(customGrantAuthentication)
                .build();

        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", null);
            throw new OAuth2AuthenticationException(error);
        }
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(), null);
        return accessToken;
    }

    private OAuth2RefreshToken generateRefreshToken(CustomGrantAuthenticationToken customGrantAuthentication, OAuth2ClientAuthenticationToken clientPrincipal, RegisteredClient registeredClient) {
        OAuth2TokenContext tokenContext2 = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(clientPrincipal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .authorizationGrantType(customGrantAuthentication.getGrantType())
                .authorizationGrant(customGrantAuthentication)
                .build();
        OAuth2Token generateRefreshToken = this.tokenGenerator.generate(tokenContext2);
        OAuth2RefreshToken oAuth2RefreshToken = new OAuth2RefreshToken(generateRefreshToken.getTokenValue(), generateRefreshToken.getIssuedAt());
        return oAuth2RefreshToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }
}
