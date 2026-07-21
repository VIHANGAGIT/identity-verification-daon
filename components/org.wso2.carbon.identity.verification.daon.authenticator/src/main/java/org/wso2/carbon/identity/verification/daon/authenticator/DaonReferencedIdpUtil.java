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

package org.wso2.carbon.identity.verification.daon.authenticator;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.verification.daon.authenticator.internal.DaonAuthenticatorDataHolder;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdpManager;

import java.util.HashMap;
import java.util.Map;

/**
 * Resolves the OIDC client configuration of the referenced Daon OIDC IDP connection.
 *
 * <p>The Daon TrustX Authenticator connection stores only the referenced Daon IDP's resource id
 * ({@code daon_idp_id}) and the login process definition ({@code daon_login_pd}); it carries no OIDC
 * credentials. Both the login authenticator and the flow executor call this helper to load the client
 * id/secret, authorize/token endpoints, scopes and enrol process definition ({@code daon_enrol_pd})
 * from the referenced IDP (by resource id) at runtime.</p>
 */
final class DaonReferencedIdpUtil {

    private static final Log LOG = LogFactory.getLog(DaonReferencedIdpUtil.class);

    private DaonReferencedIdpUtil() {
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
    static Map<String, String> resolveOidcConfig(String idpResourceId, String tenantDomain) {

        Map<String, String> config = new HashMap<>();
        if (StringUtils.isBlank(idpResourceId) || StringUtils.isBlank(tenantDomain)) {
            return config;
        }
        IdpManager idpManager = DaonAuthenticatorDataHolder.getIdpManager();
        if (idpManager == null) {
            LOG.warn("IdpManager unavailable; cannot resolve the referenced Daon IDP: " + idpResourceId);
            return config;
        }
        try {
            IdentityProvider idp = idpManager.getIdPByResourceId(idpResourceId, tenantDomain, false);
            if (idp == null) {
                LOG.warn("Referenced Daon IDP not found for resource id: " + idpResourceId);
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
                LOG.warn("Referenced Daon IDP has no authenticator configuration: " + idpResourceId);
                return config;
            }
            for (Property property : authConfig.getProperties()) {
                if (property != null && StringUtils.isNotBlank(property.getName())) {
                    config.put(property.getName(), property.getValue());
                }
            }
        } catch (IdentityProviderManagementException e) {
            LOG.error("Error resolving the referenced Daon IDP for resource id: " + idpResourceId, e);
        }
        return config;
    }

    /**
     * Resolves the name of the referenced Daon IDP connection (by resource id).
     *
     * <p>The Daon verification state is stored as a federated association against this referenced Daon
     * IDP — never against the authenticator connection itself — so that every authenticator connection
     * pointing at the same Daon IDP (e.g. separate login and registration connections) shares one
     * enrolment state.</p>
     *
     * @param idpResourceId resource id (UUID) of the referenced Daon IDP connection.
     * @param tenantDomain  tenant the connection belongs to.
     * @return the referenced IDP's name, or {@code null} if it cannot be resolved.
     */
    static String resolveIdpName(String idpResourceId, String tenantDomain) {

        if (StringUtils.isBlank(idpResourceId) || StringUtils.isBlank(tenantDomain)) {
            return null;
        }
        IdpManager idpManager = DaonAuthenticatorDataHolder.getIdpManager();
        if (idpManager == null) {
            LOG.warn("IdpManager unavailable; cannot resolve the referenced Daon IDP: " + idpResourceId);
            return null;
        }
        try {
            IdentityProvider idp = idpManager.getIdPByResourceId(idpResourceId, tenantDomain, false);
            return idp != null ? idp.getIdentityProviderName() : null;
        } catch (IdentityProviderManagementException e) {
            LOG.error("Error resolving the referenced Daon IDP name for resource id: " + idpResourceId, e);
            return null;
        }
    }
}
