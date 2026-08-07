/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.verification.daon.connector.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.internal.DaonConnectorDataHolder;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdpManager;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves the OIDC client configuration and IDP name for a Daon connection.
 *
 * <p>A Daon connection is either <b>self-contained</b> (a Daon Identity Verifier connection
 * that carries its own OIDC credentials, endpoints, scopes and enrol process definition) or
 * <b>referencing</b> (a Daon TrustX Authenticator login connection that stores only a
 * {@code daon_idp_id} pointing at a self-contained connection plus its own login process definition).
 * For a referencing connection, both the login authenticator and the flow executor call this helper to
 * load the client id/secret, authorize/token endpoints and scopes from the referenced connection (by
 * resource id) at runtime; for a self-contained connection they use its own properties directly.</p>
 */
public final class DaonReferencedIdpUtil {

    private static final Log LOG = LogFactory.getLog(DaonReferencedIdpUtil.class);

    /**
     * The authenticator property keys resolved from the referenced connection.
     *
     * <p>The OIDC keys are the ones {@code OpenIDConnectAuthenticator} / {@code OpenIDConnectExecutor} read
     * to build the authorize and token requests, so injecting them makes a referencing connection look
     * self-contained to them. The enrol process definition is resolved alongside them because it is
     * configured on the Daon Identity Verifier connection (where enrolment normally happens), yet a login
     * connection asked to enrol a user has to send it too.</p>
     *
     * <p>The login process definition is deliberately absent: it belongs to the login connection, and the
     * referenced connection must not override it.</p>
     */
    private static final List<String> REFERENCED_CONFIG_KEYS = Arrays.asList(
            OIDCAuthenticatorConstants.CLIENT_ID,
            OIDCAuthenticatorConstants.CLIENT_SECRET,
            OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL,
            OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL,
            IdentityApplicationConstants.Authenticator.OIDC.SCOPES,
            DaonConstants.DAON_ENROL_PD);

    private DaonReferencedIdpUtil() {
    }

    /**
     * Builds the authenticator properties the OIDC parent classes should act on: the connection's own
     * properties with the OIDC client credentials, endpoints, scopes and enrol process definition of the
     * <b>referenced</b> Daon Identity Verifier connection layered on top when {@code daon_idp_id} is set.
     *
     * <p>Both the login authenticator and the flow executor set the result back on their context before
     * delegating, so all authorize/token request construction stays in {@code OpenIDConnectAuthenticator}
     * / {@code OpenIDConnectExecutor} — a referencing connection is simply presented to them as a fully
     * configured OIDC connection. For a self-contained connection this is a copy of its own properties.</p>
     *
     * @param props        the connection's own authenticator properties.
     * @param tenantDomain tenant the connection belongs to.
     * @return the effective authenticator properties (never the passed-in map).
     */
    public static Map<String, String> buildEffectiveProperties(Map<String, String> props, String tenantDomain) {

        Map<String, String> effectiveProperties = new HashMap<>(props);
        Map<String, String> oidcConfig = resolveEffectiveOidcConfig(props, tenantDomain);
        for (String key : REFERENCED_CONFIG_KEYS) {
            String value = oidcConfig.get(key);
            if (StringUtils.isNotBlank(value)) {
                effectiveProperties.put(key, value);
            }
        }
        return effectiveProperties;
    }

    /**
     * Resolves the effective OIDC configuration for a Daon connection: the referenced Identity
     * Verification connection's authenticator properties when {@code daon_idp_id} is set (referencing
     * login connection), otherwise the connection's own properties (self-contained connection).
     *
     * @param props        the connection's own authenticator properties.
     * @param tenantDomain tenant the connection belongs to.
     * @return the effective OIDC configuration (own or referenced).
     */
    private static Map<String, String> resolveEffectiveOidcConfig(Map<String, String> props, String tenantDomain) {

        String idpResourceId = props.get(DaonConstants.DAON_IDP_ID);
        if (StringUtils.isNotBlank(idpResourceId)) {
            return resolveOidcConfig(idpResourceId, tenantDomain);
        }
        return props;
    }

    /**
     * Loads the OIDC authenticator properties (keyed by their standard OIDC property names, e.g.
     * {@code ClientId}, {@code ClientSecret}, {@code OAuth2AuthzEPUrl}, {@code OAuth2TokenEPUrl},
     * {@code Scopes}) from the referenced Daon IDP connection.
     *
     * @param idpResourceId resource id (UUID) of the referenced Daon IDP connection.
     * @param tenantDomain  tenant the connection belongs to.
     * @return the referenced IDP's authenticator properties; empty if it cannot be resolved.
     */
    private static Map<String, String> resolveOidcConfig(String idpResourceId, String tenantDomain) {

        Map<String, String> config = new HashMap<>();
        if (StringUtils.isBlank(idpResourceId) || StringUtils.isBlank(tenantDomain)) {
            LOG.debug("Blank Daon IDP resource id or tenant domain; nothing to resolve.");
            return config;
        }
        IdpManager idpManager = DaonConnectorDataHolder.getIdpManager();
        if (idpManager == null) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_IDP_MANAGER_UNAVAILABLE, idpResourceId));
            return config;
        }
        try {
            IdentityProvider idp = idpManager.getIdPByResourceId(idpResourceId, tenantDomain, false);
            if (idp == null) {
                LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_REFERENCED_IDP_NOT_FOUND,
                        idpResourceId));
                return config;
            }
            FederatedAuthenticatorConfig authConfig = idp.getDefaultAuthenticatorConfig();
            if (authConfig == null) {
                FederatedAuthenticatorConfig[] configs = idp.getFederatedAuthenticatorConfigs();
                if (configs != null && configs.length > 0) {
                    authConfig = configs[0];
                }
            }
            if (authConfig == null || authConfig.getProperties() == null) {
                LOG.warn(DaonExceptionMgt.errorLog(
                        ErrorMessage.ERROR_REFERENCED_IDP_NO_AUTHENTICATOR_CONFIG, idpResourceId));
                return config;
            }
            for (Property property : authConfig.getProperties()) {
                if (property != null && StringUtils.isNotBlank(property.getName())) {
                    config.put(property.getName(), property.getValue());
                }
            }
        } catch (IdentityProviderManagementException e) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_RESOLVING_REFERENCED_IDP, idpResourceId), e);
        }
        return config;
    }

    /**
     * Resolves the name of the referenced Daon Identity Verifier connection (by resource id).
     *
     * <p>The Daon verification state is stored as a federated association keyed on the Identity
     * Verification connection's name (where enrolment happens), so that every login connection
     * referencing it via {@code daon_idp_id} shares one enrolment state. A self-contained connection
     * keys on its own name instead (resolved by the caller, not here).</p>
     *
     * @param idpResourceId resource id (UUID) of the referenced Daon Identity Verifier connection.
     * @param tenantDomain  tenant the connection belongs to.
     * @return the referenced connection's name, or {@code null} if it cannot be resolved.
     */
    public static String resolveIdpName(String idpResourceId, String tenantDomain) {

        if (StringUtils.isBlank(idpResourceId) || StringUtils.isBlank(tenantDomain)) {
            LOG.debug("Blank Daon IDP resource id or tenant domain; cannot resolve the IDP name.");
            return null;
        }
        IdpManager idpManager = DaonConnectorDataHolder.getIdpManager();
        if (idpManager == null) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_IDP_MANAGER_UNAVAILABLE, idpResourceId));
            return null;
        }
        try {
            IdentityProvider idp = idpManager.getIdPByResourceId(idpResourceId, tenantDomain, false);
            if (idp == null) {
                LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_REFERENCED_IDP_NOT_FOUND,
                        idpResourceId));
                return null;
            }
            return idp.getIdentityProviderName();
        } catch (IdentityProviderManagementException e) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_RESOLVING_REFERENCED_IDP, idpResourceId), e);
            return null;
        }
    }

    /**
     * Reads the claim mappings (WSO2 local claim URI -&gt; Daon claim name) configured on the referenced
     * Daon Identity Verifier connection.
     *
     * <p>Enrolment is normally driven by the Identity Verifier connection, so its Attributes tab is where
     * the Daon claim mappings are usually configured. A login connection running an enrolment needs those
     * same mappings to tell Daon which attributes to verify the document against, and falls back to them
     * when it carries none of its own.</p>
     *
     * @param idpResourceId resource id (UUID) of the referenced Daon Identity Verifier connection.
     * @param tenantDomain  tenant the connection belongs to.
     * @return local claim URI -&gt; Daon claim name; empty when the connection or its mappings cannot be
     *         resolved.
     */
    public static Map<String, String> resolveClaimMappings(String idpResourceId, String tenantDomain) {

        Map<String, String> mappings = new HashMap<>();
        if (StringUtils.isBlank(idpResourceId) || StringUtils.isBlank(tenantDomain)) {
            LOG.debug("Blank Daon IDP resource id or tenant domain; cannot resolve the claim mappings.");
            return mappings;
        }
        IdpManager idpManager = DaonConnectorDataHolder.getIdpManager();
        if (idpManager == null) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_IDP_MANAGER_UNAVAILABLE, idpResourceId));
            return mappings;
        }
        try {
            IdentityProvider idp = idpManager.getIdPByResourceId(idpResourceId, tenantDomain, false);
            if (idp == null) {
                LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_REFERENCED_IDP_NOT_FOUND,
                        idpResourceId));
                return mappings;
            }
            if (idp.getClaimConfig() == null || idp.getClaimConfig().getClaimMappings() == null) {
                return mappings;
            }
            for (ClaimMapping claimMapping : idp.getClaimConfig().getClaimMappings()) {
                if (claimMapping == null || claimMapping.getLocalClaim() == null
                        || claimMapping.getRemoteClaim() == null) {
                    continue;
                }
                String localClaimUri = claimMapping.getLocalClaim().getClaimUri();
                String remoteClaimUri = claimMapping.getRemoteClaim().getClaimUri();
                if (StringUtils.isNotBlank(localClaimUri) && StringUtils.isNotBlank(remoteClaimUri)) {
                    mappings.put(localClaimUri, remoteClaimUri);
                }
            }
        } catch (IdentityProviderManagementException e) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_RESOLVING_REFERENCED_IDP, idpResourceId), e);
        }
        return mappings;
    }
}
