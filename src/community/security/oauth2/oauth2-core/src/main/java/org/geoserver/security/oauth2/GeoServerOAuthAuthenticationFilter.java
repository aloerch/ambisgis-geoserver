/* (c) 2016 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.oauth2;

import static com.google.common.collect.Lists.newArrayList;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.SecurityUtils;
import org.geoserver.security.config.PreAuthenticatedUserNameFilterConfig.PreAuthenticatedUserNameRoleSource;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.filter.GeoServerAuthenticationFilter;
import org.geoserver.security.filter.GeoServerLogoutFilter;
import org.geoserver.security.filter.GeoServerPreAuthenticatedUserNameFilter;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.security.impl.RoleCalculator;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.Transient;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;

/**
 * OAuth2 Authentication filter receiving/validating proxy tickets and service tickets.
 *
 * @author Alessio Fabiani, GeoSolutions
 */
public abstract class GeoServerOAuthAuthenticationFilter extends GeoServerPreAuthenticatedUserNameFilter
        implements GeoServerAuthenticationFilter, LogoutHandler {

    public static final String SESSION_COOKIE_NAME = "sessionid";
    public static final String OAUTH2_AUTHENTICATION_KEY = "oauth2.authentication";
    public static final String OAUTH2_AUTHENTICATION_TYPE_KEY = "oauth2.authenticationType";
    public static final String OAUTH2_ACCESS_TOKEN_CHECK_KEY = "oauth2.AccessTokenCheckResponse";

    public enum OAuth2AuthenticationType {
        BEARER, // this is a bearer token (meaning existing access token is in the request headers)
        USER // this is a "normal" oauth2 login (i.e. interactive user login)
    }

    OAuth2FilterConfig filterConfig;

    OAuth2RestOperations restTemplate;

    OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter("/");

    ResourceServerTokenServices tokenServices;

    GeoServerOAuth2SecurityConfiguration oauth2SecurityConfiguration;

    public GeoServerOAuthAuthenticationFilter(
            SecurityNamedServiceConfig config,
            RemoteTokenServices tokenServices,
            GeoServerOAuth2SecurityConfiguration oauth2SecurityConfiguration,
            OAuth2RestOperations oauth2RestTemplate) {
        this.filterConfig = (OAuth2FilterConfig) config;
        this.tokenServices = tokenServices;
        this.oauth2SecurityConfiguration = oauth2SecurityConfiguration;
        this.restTemplate = oauth2RestTemplate;
    }

    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);

        aep = filterConfig.getAuthenticationEntryPoint();
    }

    @Override
    public AuthenticationEntryPoint getAuthenticationEntryPoint() {
        return this.aep;
    }

    /** Try to authenticate if there is no authenticated principal */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (isStatelessBearerAuthentication()) {
            doStatelessBearerFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
            return;
        }
        // try authenticating from cache (token caching mechanism). If the authentication is found in
        // the cache, the cache key will be null and the authentication set in the security context,
        // otherwise, the cache key will be returned and the authentication in the context will remain unset
        String cacheKey = authenticateFromCache(this, (HttpServletRequest) request);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Search for an access_token on the request (simulating SSO)
        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
            String accessToken = getAccessTokenFromRequest(request);
            OAuth2AccessToken token = restTemplate.getOAuth2ClientContext().getAccessToken();

            if (accessToken != null && token != null && !token.getValue().equals(accessToken)) {
                restTemplate.getOAuth2ClientContext().setAccessToken(null);
                token = restTemplate.getOAuth2ClientContext().getAccessToken();
            }

            HttpServletRequest httpRequest = (HttpServletRequest) request;

            /*
             * This cookie works only locally, when accessing the GeoServer GUI and on the same domain. For remote access you need to logout from the
             * GeoServer GUI.
             */
            final String customSessionCookie = getCustomSessionCookieValue(httpRequest);

            if (accessToken == null
                    && customSessionCookie == null
                    && (authentication == null || authentication instanceof AnonymousAuthenticationToken)) {
                final AccessTokenRequest accessTokenRequest =
                        restTemplate.getOAuth2ClientContext().getAccessTokenRequest();
                if (accessTokenRequest != null) {
                    enhanceAccessTokenRequest(httpRequest, accessTokenRequest);
                }
            }

            if ((authentication != null && accessToken != null)
                    || (accessToken != null && token == null)
                    || authentication == null
                    || authentication instanceof AnonymousAuthenticationToken) {

                // performs full authentication (token validation, roles calculation, etc.)
                doAuthenticate((HttpServletRequest) request, (HttpServletResponse) response);

                Authentication postAuthentication =
                        SecurityContextHolder.getContext().getAuthentication();
                if (postAuthentication != null && cacheKey != null) {
                    tryCacheAuthentication((HttpServletRequest) request, cacheKey, postAuthentication);
                }
            }
        }
        chain.doFilter(request, response);
    }

    // Spring may save a context while committing the response, before our finally block.
    // Its supported transient marker prevents both early saves and anonymous removal of
    // an existing browser session's context while this request is still executing.
    @Transient
    private static final class StatelessBearerSecurityContext extends SecurityContextImpl {
        private static final long serialVersionUID = 1L;
    }

    protected boolean isStatelessBearerAuthentication() {
        return filterConfig instanceof GeoServerOAuth2FilterConfig config && config.isStatelessBearerAuthentication();
    }

    private void doStatelessBearerFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        // The surrounding persistence filter may have loaded an existing browser session.
        // Keep its context intact, but never use it to authenticate this service request or
        // replace it with the bearer identity when the persistence filter saves it again.
        SecurityContext browserContext = SecurityContextHolder.getContext();
        SecurityContextHolder.setContext(new StatelessBearerSecurityContext());
        try {
            String cacheKey = authenticateFromCache(this, request);
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                doAuthenticate(request, response);
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (authentication != null && cacheKey != null) {
                    tryCacheAuthentication(request, cacheKey, authentication);
                }
            }
            chain.doFilter(request, response);
        } finally {
            SecurityContextHolder.setContext(browserContext);
        }
    }

    /**
     * Tries to cache the authentication if the cache key is not null and the authentication is not already in the
     * cache.
     */
    protected void tryCacheAuthentication(
            HttpServletRequest request, String cacheKey, Authentication postAuthentication) {
        if (cacheAuthentication(postAuthentication, request)) {
            getSecurityManager().getAuthenticationCache().put(getName(), cacheKey, postAuthentication);
        }
    }

    /**
     * Enhance accessTokenRequest after creation by the restTemplate.
     *
     * <p>The default implementation handles {@code access_token} and state key.
     *
     * @param httpRequest
     * @param accessTokenRequest Access token request, non {@code null}
     */
    protected void enhanceAccessTokenRequest(HttpServletRequest httpRequest, AccessTokenRequest accessTokenRequest) {
        var session = httpRequest.getSession();
        var validator = (String) session.getAttribute("OIDC_CODE_VERIFIER");
        accessTokenRequest.put("code_verifier", Collections.singletonList(validator));

        if (accessTokenRequest.getStateKey() != null)
            restTemplate.getOAuth2ClientContext().removePreservedState(accessTokenRequest.getStateKey());

        if (accessTokenRequest.containsKey("access_token")) clearAccessTokenRequest(httpRequest, accessTokenRequest);
    }

    private void clearAccessTokenRequest(HttpServletRequest httpRequest, AccessTokenRequest accessTokenRequest) {
        try {
            accessTokenRequest.remove("access_token");
        } finally {
            SecurityContextHolder.clearContext();
            HttpSession session = httpRequest.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            try {
                httpRequest.logout();
            } catch (ServletException e) {
                LOGGER.fine("Servlet logout reported an exception");
            }
            LOGGER.fine("Cleaned out Session Access Token Request!");
        }
    }

    protected String getBearerToken(ServletRequest request) {
        if (request instanceof HttpServletRequest servletRequest) {
            Authentication auth = new BearerTokenExtractor().extract(servletRequest);
            if (auth != null) return SecurityUtils.getUsername(auth.getPrincipal());
        }

        return null;
    }

    protected String getParameterValue(String paramName, ServletRequest request) {
        for (Enumeration<String> iterator = request.getParameterNames(); iterator.hasMoreElements(); ) {
            final String param = iterator.nextElement();
            if (paramName.equalsIgnoreCase(param)) {
                return request.getParameter(param);
            }
        }

        return null;
    }

    /** The cache key is the authentication key (global identifier) */
    @Override
    public String getCacheKey(HttpServletRequest request) {
        final String access_token = getAccessTokenFromRequest(request);
        if (isStatelessBearerAuthentication()) {
            return access_token == null || access_token.trim().isEmpty() ? null : access_token;
        }
        return access_token != null ? access_token : getCustomSessionCookieValue(request);
    }

    protected String getCustomSessionCookieValue(HttpServletRequest request) {
        if (LOGGER.isLoggable(Level.FINE)) {
            LOGGER.fine("Inspecting the http request looking for the Custom Session ID.");
        }
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            if (LOGGER.isLoggable(Level.FINE)) {
                LOGGER.fine("Found " + cookies.length + " cookies!");
            }
            for (Cookie c : cookies) {
                if (c.getName().equalsIgnoreCase(SESSION_COOKIE_NAME)) {
                    if (LOGGER.isLoggable(Level.FINE)) {
                        LOGGER.fine("Found Custom Session cookie");
                    }
                    return c.getValue();
                }
            }
        } else {
            if (LOGGER.isLoggable(Level.FINE)) {
                LOGGER.fine("Found no cookies!");
            }
        }

        return null;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        OAuth2AccessToken token = restTemplate.getOAuth2ClientContext().getAccessToken();
        if ((token != null && token.getTokenType().equalsIgnoreCase(OAuth2AccessToken.BEARER_TYPE))
                || request.getRequestURI().endsWith(filterConfig.getLogoutEndpoint())) {

            final AccessTokenRequest accessTokenRequest =
                    restTemplate.getOAuth2ClientContext().getAccessTokenRequest();
            try {
                if (accessTokenRequest != null && accessTokenRequest.getStateKey() != null) {
                    restTemplate.getOAuth2ClientContext().removePreservedState(accessTokenRequest.getStateKey());
                    accessTokenRequest.remove("access_token");
                }
            } finally {
                SecurityContextHolder.clearContext();
                request.getSession(false).invalidate();
                try {
                    request.logout();
                } catch (ServletException e) {
                    LOGGER.fine("Servlet logout reported an exception");
                }
                LOGGER.fine("Cleaned out Session Access Token Request!");
            }

            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            Cookie[] allCookies = request.getCookies();

            for (Cookie cookie : allCookies) {
                String name = cookie.getName();
                if (name.equalsIgnoreCase("JSESSIONID")) {
                    Cookie cookieToDelete = cookie;
                    cookieToDelete.setMaxAge(-1);
                    cookieToDelete.setPath("/");
                    cookieToDelete.setComment("EXPIRING COOKIE at " + System.currentTimeMillis());
                    response.addCookie(cookieToDelete);
                }
            }

            request.setAttribute(GeoServerLogoutFilter.LOGOUT_REDIRECT_ATTR, filterConfig.getLogoutUri());
        }
    }

    @Override
    protected void doAuthenticate(HttpServletRequest request, HttpServletResponse response) {

        String principal = null;
        PreAuthenticatedAuthenticationToken result = null;
        try {
            principal = getPreAuthenticatedPrincipal(request, response);
        } catch (IOException | ServletException e1) {
            LOGGER.fine("OAuth principal resolution reported an exception");
            principal = null;
        }

        LOGGER.fine("Attempting OAuth principal authentication");

        if (principal != null && principal.trim().length() > 0) {
            if (GeoServerUser.ROOT_USERNAME.equals(principal) && !isStatelessBearerAuthentication()) {
                result = new PreAuthenticatedAuthenticationToken(
                        principal,
                        null,
                        Arrays.asList(
                                GeoServerRole.ADMIN_ROLE,
                                GeoServerRole.GROUP_ADMIN_ROLE,
                                GeoServerRole.AUTHENTICATED_ROLE));
            } else {
                Collection<GeoServerRole> roles = null;
                try {
                    roles = getRoles(request, principal);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                if (roles.contains(GeoServerRole.AUTHENTICATED_ROLE) == false)
                    roles.add(GeoServerRole.AUTHENTICATED_ROLE);

                RoleCalculator calc = new RoleCalculator(getSecurityManager().getActiveRoleService());
                if (calc != null) {
                    try {
                        roles.addAll(calc.calculateRoles(principal));
                    } catch (IOException e) {
                        LOGGER.warning("OAuth default role lookup reported an exception");
                    }
                }

                Object authenticatedPrincipal = buildAuthenticatedPrincipal(principal, roles, request);
                result = new PreAuthenticatedAuthenticationToken(authenticatedPrincipal, null, roles);
            }
            result.setDetails(getAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(result);
        }
    }

    /**
     * Builds the principal object stored in the authenticated token.
     *
     * <p>This is an extension hook intentionally receiving the resolved user name, roles, and request context so
     * subclasses can build richer principal objects (for example principals enriched from request-scoped token claims)
     * without changing this base authentication flow.
     *
     * <p>Default behavior preserves the historical contract and returns the string principal name.
     *
     * @param principalName resolved authenticated principal name
     * @param roles resolved authorities for the authenticated user
     * @param request current request, useful for request-scoped authentication attributes
     * @return principal object to store in {@link PreAuthenticatedAuthenticationToken}
     */
    protected Object buildAuthenticatedPrincipal(
            String principalName, Collection<GeoServerRole> roles, HttpServletRequest request) {
        return principalName;
    }

    @Override
    protected String getPreAuthenticatedPrincipal(HttpServletRequest request) {
        try {
            return getPreAuthenticatedPrincipal(request, null);
        } catch (IOException | ServletException e) {
            return null;
        }
    }

    protected String getPreAuthenticatedPrincipal(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, ServletException {

        if (isStatelessBearerAuthentication()) {
            return getStatelessBearerPrincipal(req);
        }

        // Make sure the REST Resource Template has been correctly configured
        configureRestTemplate();

        // Avoid retrieving the user name more than once
        /*
         * if (req.getAttribute(UserNameAlreadyRetrieved) != null) return (String) req.getAttribute(UserName);
         */

        // Search for an access_token on the request (simulating SSO)
        String accessToken = getAccessTokenFromRequest(req);
        if (accessToken != null) {
            req.setAttribute(OAUTH2_AUTHENTICATION_TYPE_KEY, OAuth2AuthenticationType.BEARER);
        } else {
            req.setAttribute(OAUTH2_AUTHENTICATION_TYPE_KEY, OAuth2AuthenticationType.USER);
        }

        if (accessToken != null) {
            restTemplate.getOAuth2ClientContext().setAccessToken(new DefaultOAuth2AccessToken(accessToken));
        }

        // Setting up OAuth2 Filter services and resource template
        filter.setRestTemplate(restTemplate);
        filter.setTokenServices(tokenServices);

        // Validating the access_token
        Authentication authentication = null;
        try {
            authentication = filter.attemptAuthentication(req, null);
            req.setAttribute(OAUTH2_AUTHENTICATION_KEY, authentication);

            // the authentication (in the extensions) should contain a Map which is the result of
            // the
            // Access Token Check Request (which will be the json result from the oidc "userinfo"
            // endpoint).
            // We move it from inside the authentication to directly to a request attributes.
            // This will make it a "peer" with the Access Token (which spring puts on the request as
            // an attribute).
            if (authentication instanceof OAuth2Authentication oAuth2Authentication) {
                Object map =
                        oAuth2Authentication.getOAuth2Request().getExtensions().get(OAUTH2_ACCESS_TOKEN_CHECK_KEY);
                if (map instanceof Map) {
                    req.setAttribute(OAUTH2_ACCESS_TOKEN_CHECK_KEY, map);
                }
            }

            LOGGER.fine("Authenticated OAuth request");
        } catch (HttpClientErrorException.Unauthorized unauthorized) {
            // this exception typically happens when the token has expired (also, if it was
            // invalid/modified)
            LOGGER.severe("OAuth token validation endpoint rejected credentials");
        } catch (Exception e) {
            if (e instanceof UserRedirectRequiredException || e instanceof InsufficientAuthenticationException) {
                if (filterConfig.getEnableRedirectAuthenticationEntryPoint()
                        || req.getRequestURI().endsWith(filterConfig.getLoginEndpoint())) {
                    // Intercepting a "UserRedirectRequiredException" and redirect to the OAuth2
                    // Provider login URI
                    if (filterConfig.isAllowUnSecureLogging()) {
                        LOGGER.log(
                                Level.FINE,
                                "OIDC: redirecting to identity provider for user login: "
                                        + this.filterConfig.buildAuthorizationUrl());
                        LOGGER.log(
                                Level.FINE,
                                "OIDC: When complete, identity provider will redirect to: "
                                        + this.filterConfig.getRedirectUri());
                    }
                    this.aep.commence(req, resp, null);
                } else {
                    if (resp.getStatus() != 302) {
                        // AEP redirection failed
                        final AccessTokenRequest accessTokenRequest =
                                restTemplate.getOAuth2ClientContext().getAccessTokenRequest();
                        if (accessTokenRequest.getPreservedState() != null
                                && accessTokenRequest.getStateKey() != null) {
                            accessTokenRequest.remove("state");
                            accessTokenRequest.remove(accessTokenRequest.getStateKey());
                            accessTokenRequest.setPreservedState(null);
                        }
                    }
                }
            } else if (e instanceof BadCredentialsException || e instanceof ResourceAccessException) {
                if (e.getCause() instanceof OAuth2AccessDeniedException) {
                    LOGGER.warning("OAuth provider denied authentication");
                } else if (e instanceof ResourceAccessException) {
                    LOGGER.severe("OAuth provider could not be reached");
                } else if (e instanceof ResourceAccessException
                        || e.getCause() instanceof OAuth2AccessDeniedException) {
                    LOGGER.log(
                            Level.WARNING,
                            "It is worth notice that if you try to validate credentials against an SSH protected Endpoint, you need either your server exposed on a secure SSL channel or OAuth2 Provider Certificate to be trusted on your JVM!");
                    LOGGER.info(
                            "Please refer to the GeoServer OAuth2 Plugin Documentation in order to find the steps for importing the SSH certificates.");
                } else {
                    LOGGER.severe("OAuth credentials were rejected");
                }
            }
        }

        return resolvePrincipal(authentication, req);
    }

    private String getStatelessBearerPrincipal(HttpServletRequest req) throws IOException {
        String accessToken = getAccessTokenFromRequest(req);
        if (accessToken == null || accessToken.trim().isEmpty()) return null;
        req.setAttribute(OAUTH2_AUTHENTICATION_TYPE_KEY, OAuth2AuthenticationType.BEARER);

        OAuth2Authentication authentication;
        try {
            // Do not dereference the session-scoped OAuth2RestOperations proxy here.
            GeoServerOAuthRemoteTokenServices services = (GeoServerOAuthRemoteTokenServices) tokenServices;
            services.setClientId(filterConfig.getCliendId());
            services.setClientSecret(filterConfig.getClientSecret());
            services.setCheckTokenEndpointUrl(filterConfig.getCheckTokenEndpointUrl());
            services.setIntrospectionEndpointUrl(filterConfig.getIntrospectionEndpointUrl());
            authentication = services.loadAuthentication(accessToken);
            if (authentication == null || !authentication.isAuthenticated()) return null;
        } catch (RuntimeException failure) {
            // Token-service exception messages and bodies can contain credentials.
            LOGGER.fine("Stateless OAuth bearer verification failed");
            return null;
        }

        req.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, accessToken);
        req.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, OAuth2AccessToken.BEARER_TYPE);
        authentication.setDetails(getAuthenticationDetailsSource().buildDetails(req));
        req.setAttribute(OAUTH2_AUTHENTICATION_KEY, authentication);
        Object claims = authentication.getOAuth2Request().getExtensions().get(OAUTH2_ACCESS_TOKEN_CHECK_KEY);
        if (claims instanceof Map) req.setAttribute(OAUTH2_ACCESS_TOKEN_CHECK_KEY, claims);
        return resolvePrincipal(authentication, req);
    }

    private String resolvePrincipal(Authentication authentication, HttpServletRequest req) throws IOException {
        String username = (authentication != null ? SecurityUtils.getUsername(authentication.getPrincipal()) : null);
        if (username != null && username.trim().length() == 0) username = null;
        try {
            if (username != null && PreAuthenticatedUserNameRoleSource.UserGroupService.equals(getRoleSource())) {
                GeoServerUserGroupService service =
                        getSecurityManager().loadUserGroupService(getUserGroupServiceName());
                GeoServerUser u = service.getUserByUsername(username);
                if (u == null && isStatelessBearerAuthentication()) {
                    // Opt-in service authentication requires a provisioned principal when the
                    // configured role authority is the local user/group service.
                    username = null;
                } else if (u != null && u.isEnabled() == false) {
                    username = null;
                    handleDisabledUser(u, req);
                }
            }
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
        req.setAttribute(UserNameAlreadyRetrieved, Boolean.TRUE);
        if (username != null) req.setAttribute(UserName, username);
        return username;
    }

    private String getAccessTokenFromRequest(ServletRequest req) {
        String accessToken = getParameterValue("access_token", req);
        if (accessToken == null) {
            accessToken = getBearerToken(req);
        }
        return accessToken;
    }

    protected void configureRestTemplate() {
        AuthorizationCodeResourceDetails details = (AuthorizationCodeResourceDetails) restTemplate.getResource();

        details.setClientId(filterConfig.getCliendId());
        details.setClientSecret(filterConfig.getClientSecret());
        ((GeoServerOAuthRemoteTokenServices) this.tokenServices).setClientId(filterConfig.getCliendId());
        ((GeoServerOAuthRemoteTokenServices) this.tokenServices).setClientSecret(filterConfig.getClientSecret());

        details.setAccessTokenUri(filterConfig.getAccessTokenUri());
        details.setUserAuthorizationUri(filterConfig.getUserAuthorizationUri());
        details.setPreEstablishedRedirectUri(filterConfig.getRedirectUri());
        ((GeoServerOAuthRemoteTokenServices) this.tokenServices)
                .setCheckTokenEndpointUrl(filterConfig.getCheckTokenEndpointUrl());
        ((GeoServerOAuthRemoteTokenServices) this.tokenServices)
                .setIntrospectionEndpointUrl(filterConfig.getIntrospectionEndpointUrl());

        details.setScope(parseScopes(filterConfig.getScopes()));
    }

    protected List<String> parseScopes(String commaSeparatedScopes) {
        List<String> scopes = newArrayList();
        Collections.addAll(scopes, commaSeparatedScopes.split(","));
        return scopes;
    }

    @Override
    protected String getPreAuthenticatedPrincipalName(HttpServletRequest request) {
        // Nothing to do; everything is handled by {@link getPreAuthenticatedPrincipal}
        return null;
    }
}
