/* (c) 2016 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.HexFormat;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.minidev.json.JSONArray;
import org.geoserver.platform.GeoServerEnvironment;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.event.RoleLoadedListener;
import org.geoserver.security.impl.AbstractGeoServerSecurityService;
import org.geoserver.security.impl.GeoServerRole;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;
import org.apache.http.impl.client.HttpClients;

/** @author Alessio Fabiani, GeoSolutions S.A.S. */
public class GeoServerRestRoleService extends AbstractGeoServerSecurityService implements GeoServerRoleService {

    static final SortedSet<String> emptyStringSet = Collections.unmodifiableSortedSet(new TreeSet<>());

    static final Map<String, String> emptyMap = Collections.emptyMap();

    // Membership and service credentials are scoped to this configured service instance.
    Cache<String, String> cachedResponses;

    /**
     * Sets a specified timeout value, in milliseconds, to be used when opening a communications link to the resource
     * referenced by this URLConnection. If the timeout expires before the connection can be established, a
     * {@link java.net.SocketTimeoutException} is raised.
     *
     * <p>A timeout of zero is interpreted as an infinite timeout.
     *
     * <p>Some non-standard implementation of this method may ignore the specified timeout. To see the connect timeout
     * set, please call getConnectTimeout().
     *
     * @param timeout an int that specifies the connect timeout value in milliseconds
     * @throws {@link IllegalArgumentException} - if the timeout parameter is negative
     */
    static final int CONN_TIMEOUT = 30000;

    /**
     * Sets the read timeout to a specified timeout, in milliseconds. A non-zero value specifies the timeout when
     * reading from Input stream when a connection is established to a resource. If the timeout expires before there is
     * data available for read, a {@link java.net.SocketTimeoutException} is raised.
     *
     * <p>A timeout of zero is interpreted as an infinite timeout.
     *
     * <p>Some non-standard implementation of this method may ignore the specified timeout. To see the read timeout set,
     * please call getReadTimeout().
     *
     * @param timeout an int that specifies the timeout value to be used in milliseconds
     * @throws {@link IllegalArgumentException} - if the timeout parameter is negative
     */
    static final int READ_TIMEOUT = 30000;

    // JsonPath/json-smart accepts JavaScript-like syntax and duplicate keys. Strict
    // membership responses require one complete unambiguous JSON document instead.
    private static final ObjectMapper STRICT_JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private RestTemplate restTemplate;

    private static String rolePrefix = "ROLE_";

    static boolean isEmpty(String property) {
        return property == null || property.isEmpty();
    }

    GeoServerRestRoleServiceConfig restRoleServiceConfig;

    private boolean convertToUpperCase = true;

    private String adminGroup;

    private String groupAdminGroup;

    protected Set<RoleLoadedListener> listeners = Collections.synchronizedSet(new HashSet<>());

    /** Default Constructor */
    public GeoServerRestRoleService(SecurityNamedServiceConfig config) throws IOException {
        initializeFromConfig(config);
    }

    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);
        restRoleServiceConfig = (GeoServerRestRoleServiceConfig) config;
        adminGroup = null;
        groupAdminGroup = null;
        restTemplate = null;
        if (restRoleServiceConfig.isStrictGeoNodeRoles()
                && (!isEmpty(restRoleServiceConfig.getAdminRoleName())
                        || !isEmpty(restRoleServiceConfig.getGroupAdminRoleName()))) {
            throw new IOException("Strict GeoNode mapping requires the authenticated admin-role endpoint");
        }
        if (!isEmpty(restRoleServiceConfig.getAdminRoleName())) {
            this.adminGroup = restRoleServiceConfig.getAdminRoleName();
        }
        if (!isEmpty(restRoleServiceConfig.getGroupAdminRoleName())) {
            this.groupAdminGroup = restRoleServiceConfig.getGroupAdminRoleName();
        }

        cachedResponses = CacheBuilder.newBuilder()
                .concurrencyLevel(restRoleServiceConfig.getCacheConcurrencyLevel())
                .maximumSize(restRoleServiceConfig.getCacheMaximumSize())
                .expireAfterWrite(restRoleServiceConfig.getCacheExpirationTime(), TimeUnit.MILLISECONDS)
                .build(); // look Ma, no CacheLoader
    }

    /* Resolve GeoServer environment placeholders */
    private String resolveEnvironmentValue(String value) {
        final GeoServerEnvironment gsEnvironment = GeoServerExtensions.bean(GeoServerEnvironment.class);

        if (gsEnvironment != null && GeoServerEnvironment.allowEnvParametrization()) {
            return (String) gsEnvironment.resolveValue(value);
        }

        return value;
    }

    /** Read only store. */
    @Override
    public boolean canCreateStore() {
        return false;
    }

    /** Read only store. */
    @Override
    public GeoServerRoleStore createStore() throws IOException {
        return null;
    }

    /** @see org.geoserver.security.GeoServerRoleService#registerRoleLoadedListener(RoleLoadedListener) */
    @Override
    public void registerRoleLoadedListener(RoleLoadedListener listener) {
        listeners.add(listener);
    }

    /** @see org.geoserver.security.GeoServerRoleService#unregisterRoleLoadedListener(RoleLoadedListener) */
    @Override
    public void unregisterRoleLoadedListener(RoleLoadedListener listener) {
        listeners.remove(listener);
    }

    /** Roles to group association is not supported */
    @Override
    public SortedSet<String> getGroupNamesForRole(GeoServerRole role) throws IOException {
        return emptyStringSet;
    }

    @Override
    public SortedSet<String> getUserNamesForRole(GeoServerRole role) throws IOException {
        final SortedSet<String> users = new TreeSet<>();

        return Collections.unmodifiableSortedSet(users);
    }

    @SuppressWarnings("unchecked")
    @Override
    public SortedSet<GeoServerRole> getRolesForUser(String username) throws IOException {
        final SortedSet<GeoServerRole> roles = new TreeSet<>();

        try {
            RestEndpointConnectionCallback callback = new RestEndpointConnectionCallback() {

                @Override
                public Object executeWithContext(String json) throws Exception {
                    if (restRoleServiceConfig.isStrictGeoNodeRoles()) {
                        return strictUserRoles(json, username);
                    }
                    try {
                        List<Object> rolesString = JsonPath.read(
                                json, restRoleServiceConfig.getUsersJSONPath().replace("${username}", username));

                        for (Object roleObj : rolesString) {
                            if (roleObj instanceof String string) {
                                populateRoles(string, roles);
                            } else if (roleObj instanceof JSONArray array) {
                                for (Object role : array) {
                                    populateRoles((String) role, roles);
                                }
                            }
                        }
                    } catch (PathNotFoundException ex) {
                        Logger.getLogger(getClass().getName()).log(Level.FINEST, null, ex);
                        roles.clear();
                        roles.add(GeoServerRole.AUTHENTICATED_ROLE);
                    }

                    SortedSet<GeoServerRole> finalRoles = Collections.unmodifiableSortedSet(fixGeoServerRoles(roles));

                    if (LOGGER.isLoggable(Level.FINE)) {
                        LOGGER.fine("Setting ROLES for User [" + username + "] to " + finalRoles);
                    }

                    return finalRoles;
                }

                private void populateRoles(String role, final SortedSet<GeoServerRole> roles) throws IOException {
                    if (role.startsWith(rolePrefix)) {
                        // remove standard role prefix
                        role = role.substring(rolePrefix.length());
                    }

                    roles.add(createRoleObject(role));
                }
            };
            return (SortedSet<GeoServerRole>) connectToRESTEndpoint(
                    resolveEnvironmentValue(restRoleServiceConfig.getBaseUrl()),
                    restRoleServiceConfig.getUsersRESTEndpoint() + "/"
                            + UriUtils.encodePathSegment(username, StandardCharsets.UTF_8),
                    restRoleServiceConfig.isStrictGeoNodeRoles()
                            ? "$.users"
                            : restRoleServiceConfig.getUsersJSONPath().replace("${username}", username),
                    resolveEnvironmentValue(restRoleServiceConfig.getAuthApiKey()),
                    callback);
        } catch (Exception ex) {
            // Never retain a prefix of a malformed role array or log a credential-bearing body.
            LOGGER.fine("REST user-role lookup failed");
            roles.clear();
        }

        return Collections.unmodifiableSortedSet(roles);
    }

    private static Map<?, ?> strictObject(String json) throws IOException {
        Object value = STRICT_JSON.readValue(json, Object.class);
        if (!(value instanceof Map<?, ?> object)) throw new IOException("Invalid GeoNode JSON object");
        return object;
    }

    private List<String> strictRoleNames(String json) throws IOException {
        Object value = strictObject(json).get("groups");
        if (!(value instanceof List<?> groups)) throw new IOException("Invalid GeoNode role-list response");
        List<String> result = new ArrayList<>();
        for (Object group : groups) {
            if (!(group instanceof String role)) throw new IOException("Invalid GeoNode role value");
            strictRole(role);
            result.add(role);
        }
        return result;
    }

    private GeoServerRole strictRole(String role) throws IOException {
        if (role == null || !role.matches("[a-z][a-z0-9_-]{0,149}") || role.startsWith("role_")
                || Set.of("administrator", "group_admin", "group-admin", "authenticated", "anonymous", "any", "root").contains(role)) {
            throw new IOException("Noncanonical or reserved GeoNode role");
        }
        return createRoleObject(role);
    }

    private SortedSet<GeoServerRole> strictUserRoles(String json, String username) throws IOException {
        Object usersValue = strictObject(json).get("users");
        if (!(usersValue instanceof List<?> users)) throw new IOException("Invalid GeoNode users response");
        SortedSet<GeoServerRole> result = new TreeSet<>();
        if (users.isEmpty()) return Collections.unmodifiableSortedSet(result);
        if (users.size() != 1 || !(users.get(0) instanceof Map<?, ?> user)
                || !username.equals(user.get("username")) || !(user.get("groups") instanceof List<?> groups)) {
            throw new IOException("GeoNode role response does not bind the exact requested identity");
        }
        for (Object group : groups) {
            if (!(group instanceof String role)) throw new IOException("Invalid GeoNode role value");
            result.add(strictRole(role));
        }
        if (!result.isEmpty()) {
            GeoServerRole admin = getAdminRole();
            if (admin == null) throw new IOException("GeoNode administrative mapping unavailable");
            if (result.contains(admin)) {
                result.clear();
                result.add(GeoServerRole.ADMIN_ROLE);
            }
        }
        return Collections.unmodifiableSortedSet(result);
    }

    protected SortedSet<GeoServerRole> fixGeoServerRoles(SortedSet<GeoServerRole> roles) {
        // Check if is an ADMIN
        GeoServerRole adminRole = getAdminRole();
        if (roles.contains(GeoServerRole.ADMIN_ROLE) || (adminRole != null && roles.contains(adminRole))) {
            roles.clear();
            roles.add(GeoServerRole.ADMIN_ROLE);
        }

        // Check if Role Anonymous is present other than other roles
        if (roles.size() > 1 && roles.contains(GeoServerRole.ANONYMOUS_ROLE)) {
            roles.remove(GeoServerRole.ANONYMOUS_ROLE);
        }

        return roles;
    }

    @Override
    public SortedSet<GeoServerRole> getRolesForGroup(String groupname) throws IOException {
        SortedSet<GeoServerRole> set = new TreeSet<>();
        GeoServerRole role = getRoleByName(groupname);
        if (role != null) {
            set.add(role);
        }

        return Collections.unmodifiableSortedSet(set);
    }

    @SuppressWarnings("unchecked")
    @Override
    public SortedSet<GeoServerRole> getRoles() throws IOException {
        final SortedSet<GeoServerRole> roles = new TreeSet<>();

        try {
            RestEndpointConnectionCallback callback = new RestEndpointConnectionCallback() {

                @Override
                public Object executeWithContext(String json) throws Exception {
                    try {
                        List<String> rolesString = restRoleServiceConfig.isStrictGeoNodeRoles()
                                ? strictRoleNames(json)
                                : JsonPath.read(json, restRoleServiceConfig.getRolesJSONPath());

                        for (String role : rolesString) {
                            if (restRoleServiceConfig.isStrictGeoNodeRoles()) {
                                roles.add(strictRole(role));
                                continue;
                            }
                            if (role.startsWith(rolePrefix)) {
                                // remove standard role prefix
                                role = role.substring(rolePrefix.length());
                            }

                            roles.add(createRoleObject(role));
                        }
                    } catch (PathNotFoundException ex) {
                        Logger.getLogger(getClass().getName()).log(Level.FINEST, null, ex);
                    }

                    return Collections.unmodifiableSortedSet(roles);
                }
            };
            return (SortedSet<GeoServerRole>) connectToRESTEndpoint(
                    resolveEnvironmentValue(restRoleServiceConfig.getBaseUrl()),
                    restRoleServiceConfig.getRolesRESTEndpoint(),
                    restRoleServiceConfig.getRolesJSONPath(),
                    resolveEnvironmentValue(restRoleServiceConfig.getAuthApiKey()),
                    callback);
        } catch (Exception ex) {
            LOGGER.fine("REST role-list lookup failed");
            roles.clear();
        }

        return Collections.unmodifiableSortedSet(roles);
    }

    @Override
    public Map<String, String> getParentMappings() throws IOException {
        return emptyMap;
    }

    @Override
    public GeoServerRole createRoleObject(String role) throws IOException {
        return new GeoServerRole(rolePrefix + (convertToUpperCase ? role.toUpperCase(Locale.ROOT) : role));
    }

    @Override
    public GeoServerRole getParentRole(GeoServerRole role) throws IOException {
        return null;
    }

    @Override
    public GeoServerRole getRoleByName(String role) throws IOException {
        if (role.startsWith(rolePrefix)) {
            // remove standard role prefix
            role = role.substring(rolePrefix.length());
        }
        final String roleName = role;

        try {
            RestEndpointConnectionCallback callback = new RestEndpointConnectionCallback() {

                @Override
                public Object executeWithContext(String json) throws Exception {
                    try {
                        List<String> rolesString = restRoleServiceConfig.isStrictGeoNodeRoles()
                                ? strictRoleNames(json)
                                : JsonPath.read(json, restRoleServiceConfig.getRolesJSONPath());

                        for (String targetRole : rolesString) {
                            if (targetRole.startsWith(rolePrefix)) {
                                // remove standard role prefix
                                targetRole = targetRole.substring(rolePrefix.length());
                            }

                            if (roleName.equalsIgnoreCase(targetRole)) {
                                return createRoleObject(roleName);
                            }
                        }
                    } catch (PathNotFoundException ex) {
                        Logger.getLogger(getClass().getName()).log(Level.FINEST, null, ex);
                    }

                    return null;
                }
            };
            return (GeoServerRole) connectToRESTEndpoint(
                    resolveEnvironmentValue(restRoleServiceConfig.getBaseUrl()),
                    restRoleServiceConfig.getRolesRESTEndpoint(),
                    restRoleServiceConfig.getRolesJSONPath(),
                    resolveEnvironmentValue(restRoleServiceConfig.getAuthApiKey()),
                    callback);
        } catch (Exception ex) {
            Logger.getLogger(getClass().getName()).log(Level.FINEST, null, ex);
        }

        return null;
    }

    @Override
    public void load() throws IOException {
        // Not needed
    }

    @Override
    public Properties personalizeRoleParams(
            String roleName, Properties roleParams, String userName, Properties userProps) throws IOException {
        return null;
    }

    @Override
    public GeoServerRole getAdminRole() {
        if (adminGroup == null) {
            try {
                RestEndpointConnectionCallback callback = new RestEndpointConnectionCallback() {

                    @Override
                    public Object executeWithContext(String json) throws Exception {
                        try {
                            if (restRoleServiceConfig.isStrictGeoNodeRoles()) {
                                Object targetRole = strictObject(json).get("adminRole");
                                // The controlled endpoint reserves this role exclusively for superusers.
                                if (!"admin".equals(targetRole)) throw new IOException("Invalid GeoNode admin mapping");
                                return strictRole("admin");
                            }
                            String targetRole = JsonPath.read(json, restRoleServiceConfig.getAdminRoleJSONPath());

                            if (targetRole.startsWith(rolePrefix)) {
                                // remove standard role prefix
                                targetRole = targetRole.substring(rolePrefix.length());
                            }

                            return createRoleObject(targetRole);
                        } catch (PathNotFoundException ex) {
                            Logger.getLogger(getClass().getName()).log(Level.FINEST, null, ex);
                        }

                        return null;
                    }
                };
                return (GeoServerRole) connectToRESTEndpoint(
                        resolveEnvironmentValue(restRoleServiceConfig.getBaseUrl()),
                        restRoleServiceConfig.getAdminRoleRESTEndpoint(),
                        restRoleServiceConfig.getAdminRoleJSONPath(),
                        resolveEnvironmentValue(restRoleServiceConfig.getAuthApiKey()),
                        callback);
            } catch (Exception ex) {
                LOGGER.fine("REST administrative-role lookup failed");
            }
            return null;
        }

        try {
            return getRoleByName(adminGroup);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public GeoServerRole getGroupAdminRole() {
        if (groupAdminGroup == null) {
            return getAdminRole();
        }
        try {
            return getRoleByName(groupAdminGroup);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int getRoleCount() throws IOException {
        return getRoles().size();
    }

    /** @return the restTemplate */
    public RestTemplate getRestTemplate() {
        if (restTemplate == null) {
            restTemplate = restTemplate();
        }

        return restTemplate;
    }

    /** @param restTemplate the restTemplate to set */
    public void setRestTemplate(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    private RestTemplate restTemplate() {
        return new RestTemplate(clientHttpRequestFactory());
    }

    private ClientHttpRequestFactory clientHttpRequestFactory() {
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();
        factory.setReadTimeout(restRoleServiceConfig.getReadTimeout());
        factory.setConnectTimeout(restRoleServiceConfig.getConnectTimeout());
        factory.setConnectionRequestTimeout(restRoleServiceConfig.getConnectTimeout());
        // An endpoint redirect must not forward the separate role-service credential.
        factory.setHttpClient(HttpClients.custom().disableRedirectHandling().build());
        return factory;
    }

    /** Execute REST CALL, and then call the given callback on HTTP JSON Response. */
    protected Object connectToRESTEndpoint(
            final String roleRESTBaseURL,
            final String roleRESTEndpoint,
            final String roleJSONPath,
            final String authApiKey,
            RestEndpointConnectionCallback callback)
            throws Exception {
        final String restEndPoint = roleRESTBaseURL + roleRESTEndpoint + roleJSONPath;
        // First search on cache
        final String hash = cacheKey(restEndPoint, authApiKey);

        try {
            // If the key wasn't in the "easy to compute" group, we need to
            // do things the hard way.
            Callable<String> authorization = new Callable<>() {

                @Override
                public String call() throws Exception {

                    LOGGER.fine("GeoServer REST Role Service CACHE MISS for '" + restEndPoint + "'");
                    try {
                        final URI baseURI = new URI(roleRESTBaseURL);

                        URL url = baseURI.resolve(roleRESTEndpoint).toURL();

                        ClientHttpRequest req =
                                getRestTemplate().getRequestFactory().createRequest(url.toURI(), HttpMethod.GET);

                        if (authApiKey != null) {
                            req.getHeaders().add("Authorization", "ApiKey " + authApiKey);
                        }
                        try (ClientHttpResponse res = req.execute()) {
                            int status = res.getRawStatusCode();

                            switch (status) {
                                case 200:
                                case 201:
                                    try (BufferedReader br = new BufferedReader(new InputStreamReader(res.getBody()))) {
                                        StringBuilder sb = new StringBuilder();
                                        String line;
                                        while ((line = br.readLine()) != null) {
                                            sb.append(line + "\n");
                                        }
                                        return sb.toString();
                                    }
                            }
                        }
                    } catch (URISyntaxException | IOException ex) {
                        Logger.getLogger(getClass().getName()).log(Level.FINEST, null, ex);
                    }

                    return null;
                }
            };
            final String cachedResponse = cachedResponses.get(hash, authorization);

            return callback.executeWithContext(cachedResponse);
        } catch (ExecutionException e) {
            // Preserve failure as failure: callers must not treat null as a valid role set.
            throw new IOException("REST role lookup unavailable");
        }
    }

    private static String cacheKey(String endpoint, String credential) throws NoSuchAlgorithmException {
        // Credential rotation cannot hit a response authorized with the previous key.
        return getHash(endpoint + "\u0000" + (credential == null ? "" : credential));
    }

    private static String getHash(String stringToEncrypt) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(stringToEncrypt.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(messageDigest.digest());
    }

    /**
     * Callback interface to be used in the REST call methods for performing operations on individually HTTP JSON
     * responses.
     *
     * @author Alessio Fabiani, GeoSolutions S.A.S.
     */
    interface RestEndpointConnectionCallback {

        /**
         * Perform specific operations accordingly to the caller needs.
         *
         * @param json the <code>JSON</code> string to perform an operation on.
         */
        Object executeWithContext(final String json) throws Exception;
    }
}
