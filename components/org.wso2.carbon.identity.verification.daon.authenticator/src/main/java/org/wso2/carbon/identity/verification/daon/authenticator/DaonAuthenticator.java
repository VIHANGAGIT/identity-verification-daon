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
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonClientException;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;
import org.wso2.carbon.identity.verification.daon.connector.web.DaonAPIClient;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.ACR_VALUES_PARAM;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.COMMON_AUTH_ENDPOINT;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.DAON_IDP_ID;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.DAON_LOGIN_PD;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.PARAM_CODE;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.PARAM_STATE;

/**
 * Daon TrustX federated authenticator (login step) for the Daon IDP.
 *
 * <p>Performs an OIDC Authorization Code flow against Daon. Client credentials, endpoints and scope
 * are read from the connection's own authenticator config (standard federated OIDC keys).</p>
 *
 * <p>Daon runs as a step after the user is identified, and only for users already enrolled with Daon —
 * i.e. those with a <b>federated association</b> with this Daon IDP (no custom user claims). The OIDC
 * request always carries the Daon {@code preferred_username} (from the association) as {@code login_hint}
 * for face re-verification, together with the configured <b>login process definition</b> (sent as
 * {@code acr_values}). A user with no Daon association is not enrolled: the login flow fails with an
 * error rather than attempting enrolment (enrolment happens in the registration flow).</p>
 */
public class DaonAuthenticator extends OpenIDConnectAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = 1L;

    @Override
    public String getName() {
        return DaonAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return DaonAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {
        return StringUtils.isNotBlank(request.getParameter(PARAM_CODE))
                && StringUtils.isNotBlank(request.getParameter(PARAM_STATE));
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(PARAM_STATE);
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                  AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> props = context.getAuthenticatorProperties();
        // OIDC credentials/endpoints live on the referenced Daon IDP connection, not on this
        // authenticator connection; resolve them by the configured Daon IDP id.
        Map<String, String> oidcConfig = DaonReferencedIdpUtil.resolveOidcConfig(
                props.get(DAON_IDP_ID), context.getTenantDomain());
        String clientId = oidcConfig.get(OIDCAuthenticatorConstants.CLIENT_ID);
        String authEndpoint = oidcConfig.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);
        if (StringUtils.isBlank(authEndpoint) || StringUtils.isBlank(clientId)) {
            throw new AuthenticationFailedException(
                    "Could not resolve the referenced Daon IDP's OIDC configuration. Check the "
                            + "Daon IDP ID configured on the Daon TrustX Authenticator connection.");
        }
        String scope = oidcConfig.get(IdentityApplicationConstants.Authenticator.OIDC.SCOPES);
        if (StringUtils.isBlank(scope)) {
            scope = OIDCAuthenticatorConstants.OAUTH_OIDC_SCOPE;
        }
        String redirectUri = buildCallbackUrl(request);
        String state = context.getContextIdentifier();

        // Login only serves users already enrolled with Daon: the association's federated user id is the
        // Daon preferred_username, always sent as login_hint for face re-verification. A user with no
        // Daon association is not enrolled, so the login flow cannot verify them.
        String daonSubject = resolveDaonSubject(context);
        if (StringUtils.isBlank(daonSubject)) {
            throw new AuthenticationFailedException(
                    "The user is not enrolled with Daon TrustX. Complete Daon identity verification "
                            + "before using Daon TrustX as a login step.");
        }
        String processDefinition = props.get(DAON_LOGIN_PD);

        try {
            StringBuilder url = new StringBuilder(authEndpoint)
                    .append("?response_type=code")
                    .append("&client_id=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8))
                    .append("&scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8))
                    .append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8))
                    .append("&redirect_uri=").append(URLEncoder.encode(redirectUri, StandardCharsets.UTF_8))
                    .append("&login_hint=").append(URLEncoder.encode(daonSubject, StandardCharsets.UTF_8));
            if (StringUtils.isNotBlank(processDefinition)) {
                url.append("&").append(ACR_VALUES_PARAM).append("=")
                        .append(URLEncoder.encode(processDefinition, StandardCharsets.UTF_8));
            }
            response.sendRedirect(url.toString());
            context.setCurrentAuthenticator(getName());
        } catch (IOException e) {
            throw new AuthenticationFailedException("Failed to redirect to Daon authorization URL.", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                  AuthenticationContext context)
            throws AuthenticationFailedException {

        String code = request.getParameter(PARAM_CODE);
        String state = request.getParameter(PARAM_STATE);

        if (!context.getContextIdentifier().equals(state)) {
            throw new AuthenticationFailedException("State parameter mismatch in Daon callback.");
        }

        Map<String, String> props = context.getAuthenticatorProperties();
        // Resolve the OIDC credentials/token endpoint from the referenced Daon IDP connection.
        Map<String, String> oidcConfig = DaonReferencedIdpUtil.resolveOidcConfig(
                props.get(DAON_IDP_ID), context.getTenantDomain());
        String clientId = oidcConfig.get(OIDCAuthenticatorConstants.CLIENT_ID);
        String clientSecret = oidcConfig.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
        String tokenEndpoint = oidcConfig.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
        if (StringUtils.isBlank(tokenEndpoint) || StringUtils.isBlank(clientId)) {
            throw new AuthenticationFailedException(
                    "Could not resolve the referenced Daon IDP's OIDC configuration. Check the "
                            + "Daon IDP ID configured on the Daon TrustX Authenticator connection.");
        }
        String redirectUri = buildCallbackUrl(request);

        JSONObject idTokenClaims;
        try {
            JSONObject tokenResponse = DaonAPIClient.exchangeCodeForTokens(
                    tokenEndpoint, clientId, clientSecret, code, redirectUri);
            String idToken = tokenResponse.optString(DaonConstants.ID_TOKEN);
            idTokenClaims = DaonAPIClient.parseIdToken(idToken);
        } catch (DaonClientException | DaonServerException e) {
            throw new AuthenticationFailedException("Failed to exchange code for tokens.", e);
        }

        String preferredUsername = idTokenClaims.optString(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM, null);
        String subject = StringUtils.isNotBlank(preferredUsername)
                ? preferredUsername : idTokenClaims.optString("sub", null);
        if (StringUtils.isBlank(subject)) {
            throw new AuthenticationFailedException("No subject found in Daon ID token.");
        }

        // Login serves only already-enrolled users (verified via login_hint), so the Daon association
        // already exists — nothing to create here.
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(subject);
        context.setSubject(authenticatedUser);
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> properties = new ArrayList<>();

        properties.add(buildProperty(DAON_IDP_ID, "Daon IDP ID", false,
                "Resource ID (UUID) of the Daon TrustX IDP connection whose OIDC client credentials and "
                        + "endpoints this authenticator uses.", 0));
        properties.add(buildProperty(DAON_LOGIN_PD, "Login Process Definition", false,
                "Daon process definition used for the login and password-recovery (re-verification) "
                        + "flows, as <ProcessDefinitionName:Version>, sent as acr_values. Enrolment "
                        + "flows use the enrol process definition configured on the referenced Daon "
                        + "TrustX IDP.", 1));
        return properties;
    }

    private Property buildProperty(String name, String displayName, boolean confidential,
                                   String description, int displayOrder) {

        Property property = new Property();
        property.setName(name);
        property.setDisplayName(displayName);
        property.setRequired(false);
        property.setConfidential(confidential);
        property.setDescription(description);
        property.setDisplayOrder(displayOrder);
        return property;
    }

    /**
     * Resolves the Daon {@code preferred_username} (used as {@code login_hint}) for the identified local
     * user from its federated association with the Daon IDP.
     *
     * <p>The association is stored against a normalised user (bare username + userstore domain + tenant)
     * by {@link DaonFederatedAssociationListener}, so the identified user is rebuilt the same way via
     * {@link DaonFederatedAssociationUtil#buildUser(String, String)} before the lookup — otherwise a
     * domain-qualified {@code AuthenticatedUser} name fails to resolve and an enrolled user is wrongly
     * treated as not enrolled.</p>
     *
     * <p>The association is keyed to the <b>referenced Daon IDP</b> (resolved from {@code daon_idp_id}),
     * not this authenticator connection, so a user enrolled through one Daon TrustX Authenticator
     * connection (e.g. the registration one) is recognised by any other connection pointing at the same
     * Daon IDP (e.g. the login one).</p>
     */
    private String resolveDaonSubject(AuthenticationContext context) {

        AuthenticatedUser authenticatedUser = context.getLastAuthenticatedUser();
        if (authenticatedUser == null) {
            return null;
        }
        String daonIdpName = DaonReferencedIdpUtil.resolveIdpName(
                context.getAuthenticatorProperties().get(DAON_IDP_ID), context.getTenantDomain());
        if (StringUtils.isBlank(daonIdpName)) {
            return null;
        }
        String username = UserCoreUtil.removeDomainFromName(authenticatedUser.getUserName());
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        if (StringUtils.isNotBlank(userStoreDomain)) {
            username = userStoreDomain + "/" + username;
        }
        User associationUser =
                DaonFederatedAssociationUtil.buildUser(username, authenticatedUser.getTenantDomain());
        return DaonFederatedAssociationUtil.getAssociatedDaonSubject(associationUser, daonIdpName);
    }

    private String buildCallbackUrl(HttpServletRequest request) {
        return request.getScheme() + "://" + request.getServerName() + ":"
                + request.getServerPort() + COMMON_AUTH_ENDPOINT;
    }
}
