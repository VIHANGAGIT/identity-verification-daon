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
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.DAON_ENROL_PD;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.DAON_IDP_ID;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.DAON_LOGIN_PD;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.PARAM_CODE;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.PARAM_STATE;

/**
 * Daon TrustX federated authenticator (login step).
 *
 * <p>Performs an OIDC Authorization Code flow against Daon. A connection can be configured in one of two
 * ways, distinguished by whether it sets {@code daon_idp_id}:</p>
 * <ul>
 *   <li><b>Self-contained</b> (a "Daon Identity Verifier" connection): no {@code daon_idp_id};
 *       the OIDC client credentials, endpoints and scope live on the connection's own authenticator
 *       config, and the federated association is keyed on this connection's own name.</li>
 *   <li><b>Referencing</b> (a "Daon TrustX Authenticator" login connection): sets {@code daon_idp_id} to
 *       the resource id of a self-contained Daon Identity Verifier connection; the OIDC
 *       config and the association key (IDP name) are resolved from that referenced connection, so every
 *       login connection referencing the same one shares a single enrolment.</li>
 * </ul>
 *
 * <p>Daon runs as a step after the user is identified, and only for users already enrolled with Daon —
 * i.e. those with a <b>federated association</b> with the (own or referenced) Daon IDP. The OIDC request
 * always carries the Daon {@code preferred_username} (from the association) as {@code login_hint} for
 * face re-verification, together with the configured <b>login process definition</b> (sent as
 * {@code acr_values}). A user with no Daon association is not enrolled: the login flow fails with an
 * error rather than attempting enrolment (enrolment happens in the registration/invited-user flow).</p>
 */
public class DaonAuthenticator extends OpenIDConnectAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = 1L;
    private static final Log LOG = LogFactory.getLog(DaonAuthenticator.class);

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
        // Claim both the success callback (code + state) and the OAuth2 error callback (error + state), so an
        // error is handled here instead of the framework silently re-initiating (redirecting back to Daon).
        if (StringUtils.isBlank(request.getParameter(PARAM_STATE))) {
            return false;
        }
        return StringUtils.isNotBlank(request.getParameter(PARAM_CODE))
                || StringUtils.isNotBlank(request.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR));
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
        // A referencing login connection resolves its OIDC config from the referenced Daon TrustX
        // Identity Verifier connection; a self-contained connection carries it on its own props.
        Map<String, String> oidcConfig =
                DaonReferencedIdpUtil.resolveEffectiveOidcConfig(props, context.getTenantDomain());
        String clientId = oidcConfig.get(OIDCAuthenticatorConstants.CLIENT_ID);
        String authEndpoint = oidcConfig.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);
        if (StringUtils.isBlank(authEndpoint) || StringUtils.isBlank(clientId)) {
            throw new AuthenticationFailedException(
                    "Could not resolve the Daon OIDC configuration. For a login connection, check the "
                            + "Daon Verifier ID it references; for a Daon Identity Verifier "
                            + "connection, check its own client id and endpoint configuration.");
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

        // Daon can return a standard OAuth2 error (in place of a code) when the user cancels/declines the
        // verification or Daon fails. Handle it generically off the standard error param; log the raw
        // values so Daon's specific verification-failure codes can be mapped later if needed.
        String error = request.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR);
        if (StringUtils.isNotBlank(error)) {
            String errorDescription = request.getParameter(DaonAuthenticatorConstants.OAUTH2_ERROR_DESCRIPTION);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Daon returned an error on the login callback. error=" + error
                        + ", error_description=" + errorDescription);
            }
            throw new AuthenticationFailedException(
                    DaonCallbackErrors.resolveUserFacingMessage(error, errorDescription));
        }

        Map<String, String> props = context.getAuthenticatorProperties();
        // Resolve the OIDC credentials/token endpoint from the referenced connection (login connection)
        // or from this connection's own props (self-contained Identity Verifier connection).
        Map<String, String> oidcConfig =
                DaonReferencedIdpUtil.resolveEffectiveOidcConfig(props, context.getTenantDomain());
        String clientId = oidcConfig.get(OIDCAuthenticatorConstants.CLIENT_ID);
        String clientSecret = oidcConfig.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
        String tokenEndpoint = oidcConfig.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
        if (StringUtils.isBlank(tokenEndpoint) || StringUtils.isBlank(clientId)) {
            throw new AuthenticationFailedException(
                    "Could not resolve the Daon OIDC configuration. For a login connection, check the "
                            + "Daon Verifier ID it references; for a Daon Identity Verifier "
                            + "connection, check its own client id and endpoint configuration.");
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

        // Both the self-contained (Identity Verifier) and the referencing (login) connection are
        // this same authenticator type; advertise the union of keys used by either so the framework
        // recognises them. Which subset is shown/used is driven by the connection template and by the
        // presence of daon_idp_id at runtime. None are mandatory at the type level.
        List<Property> properties = new ArrayList<>();

        properties.add(buildProperty(OIDCAuthenticatorConstants.CLIENT_ID, "Client ID", false,
                "Daon TrustX OIDC Client ID (self-contained Identity Verifier connection).", 0));
        properties.add(buildProperty(OIDCAuthenticatorConstants.CLIENT_SECRET, "Client Secret", true,
                "Daon TrustX OIDC Client Secret (self-contained Identity Verifier connection).", 1));
        properties.add(buildProperty(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL, "Authorization Endpoint URL",
                false, "Daon TrustX OIDC authorization endpoint URL "
                        + "(self-contained Identity Verifier connection).", 2));
        properties.add(buildProperty(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, "Token Endpoint URL",
                false, "Daon TrustX OIDC token endpoint URL "
                        + "(self-contained Identity Verifier connection).", 3));
        properties.add(buildProperty(IdentityApplicationConstants.Authenticator.OIDC.SCOPES, "Scopes", false,
                "OIDC scopes to request from Daon, e.g. openid profile document "
                        + "(self-contained Identity Verifier connection).", 4));
        properties.add(buildProperty(DAON_IDP_ID, "Daon Verifier ID", false,
                "Resource ID (UUID) of the Daon Identity Verifier connection whose OIDC client "
                        + "credentials and endpoints a login connection uses. Leave blank for a "
                        + "self-contained Identity Verifier connection.", 5));
        properties.add(buildProperty(DAON_ENROL_PD, "Enrol Process Definition", false,
                "Daon process definition for the enrolment flows (registration and invited-user), as "
                        + "<ProcessDefinitionName:Version>, sent as acr_values "
                        + "(self-contained Identity Verifier connection).", 6));
        properties.add(buildProperty(DAON_LOGIN_PD, "Login Process Definition", false,
                "Daon process definition for the login and password-recovery (re-verification) flows, as "
                        + "<ProcessDefinitionName:Version>, sent as acr_values (login connection).", 7));
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
     * <p>The association is keyed on the resolved Daon IDP name — for a login connection the
     * <b>referenced</b> Identity Verifier connection (from {@code daon_idp_id}), for a self-contained
     * connection its <b>own</b> name — so a user enrolled through the Identity Verifier connection is
     * recognised by every login connection referencing it.</p>
     */
    private String resolveDaonSubject(AuthenticationContext context) {

        AuthenticatedUser authenticatedUser = context.getLastAuthenticatedUser();
        if (authenticatedUser == null) {
            return null;
        }
        String daonIdpName = resolveDaonIdpName(context);
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

    /**
     * Resolves the Daon IDP name the federated association is keyed on: the referenced Identity
     * Verification connection's name when {@code daon_idp_id} is set (login connection), otherwise this
     * connection's own name (self-contained connection).
     */
    private String resolveDaonIdpName(AuthenticationContext context) {

        String idpResourceId = context.getAuthenticatorProperties().get(DAON_IDP_ID);
        if (StringUtils.isNotBlank(idpResourceId)) {
            return DaonReferencedIdpUtil.resolveIdpName(idpResourceId, context.getTenantDomain());
        }
        return context.getExternalIdP() != null ? context.getExternalIdP().getIdPName() : null;
    }

    private String buildCallbackUrl(HttpServletRequest request) {
        return request.getScheme() + "://" + request.getServerName() + ":"
                + request.getServerPort() + COMMON_AUTH_ENDPOINT;
    }
}
