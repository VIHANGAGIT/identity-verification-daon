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
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonClientException;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;
import org.wso2.carbon.identity.verification.daon.connector.web.DaonAPIClient;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.ACR_VALUES_PARAM;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.COMMON_AUTH_ENDPOINT;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.DAON_ENROL_PD;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.DAON_LOGIN_PD;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.PARAM_CODE;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.PARAM_STATE;

/**
 * Daon TrustX federated authenticator (login step) for the Daon IDP.
 *
 * <p>Performs an OIDC Authorization Code flow against Daon. Client credentials, endpoints and scope
 * are read from the connection's own authenticator config (standard federated OIDC keys).</p>
 *
 * <p>Daon runs as a step after the user is identified. Whether the user is Daon-verified is determined
 * by the presence of a <b>federated association</b> with this Daon IDP (no custom user claims). A
 * verified user re-verifies with the <b>Login/Auth PD</b> (with {@code login_hint} taken from the
 * association); a not-yet-verified user goes through the <b>Enrol PD</b>, and on success an association
 * (local user &lt;-&gt; Daon {@code preferred_username}) is created.</p>
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
        String clientId = props.get(OIDCAuthenticatorConstants.CLIENT_ID);
        String authEndpoint = props.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);
        if (StringUtils.isBlank(authEndpoint)) {
            throw new AuthenticationFailedException("Authorization endpoint not configured in the Daon connection.");
        }
        String scope = props.get(IdentityApplicationConstants.Authenticator.OIDC.SCOPES);
        if (StringUtils.isBlank(scope)) {
            scope = OIDCAuthenticatorConstants.OAUTH_OIDC_SCOPE;
        }
        String redirectUri = buildCallbackUrl(request);
        String state = context.getContextIdentifier();

        // Verified <=> the user has a federated association with this Daon IDP; the association's
        // federated user id is the Daon preferred_username used as login_hint.
        AuthenticatedUser user = context.getLastAuthenticatedUser();
        String daonSubject = DaonFederatedAssociationUtil.getAssociatedDaonSubject(user, getIdpName(context));
        boolean verified = daonSubject != null;
        String processDefinition = verified ? props.get(DAON_LOGIN_PD) : props.get(DAON_ENROL_PD);

        try {
            StringBuilder url = new StringBuilder(authEndpoint)
                    .append("?response_type=code")
                    .append("&client_id=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8))
                    .append("&scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8))
                    .append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8))
                    .append("&redirect_uri=").append(URLEncoder.encode(redirectUri, StandardCharsets.UTF_8));
            if (verified && StringUtils.isNotBlank(daonSubject)) {
                url.append("&login_hint=").append(URLEncoder.encode(daonSubject, StandardCharsets.UTF_8));
            }
            if (StringUtils.isNotBlank(processDefinition)) {
                url.append("&").append(ACR_VALUES_PARAM).append("=")
                        .append(URLEncoder.encode(processDefinition, StandardCharsets.UTF_8));
            }
            if (!verified) {
                // Enrolment: request verified_claims so the identity can be captured.
                List<String> daonClaimNames = new ArrayList<>(getIdpClaimMappings(context).values());
                if (!daonClaimNames.isEmpty()) {
                    url.append("&claims=").append(URLEncoder.encode(
                            DaonAPIClient.buildClaimsParam(daonClaimNames), StandardCharsets.UTF_8));
                }
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
        String clientId = props.get(OIDCAuthenticatorConstants.CLIENT_ID);
        String clientSecret = props.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
        String tokenEndpoint = props.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
        if (StringUtils.isBlank(tokenEndpoint)) {
            throw new AuthenticationFailedException("Token endpoint not configured in the Daon connection.");
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

        // Enrolment: if the prior-step user is not yet associated with Daon, create the association now.
        AuthenticatedUser user = context.getLastAuthenticatedUser();
        String idpName = getIdpName(context);
        if (user != null && DaonFederatedAssociationUtil.getAssociatedDaonSubject(user, idpName) == null
                && StringUtils.isNotBlank(preferredUsername)) {
            DaonFederatedAssociationUtil.createAssociation(user, idpName, preferredUsername);
        }

        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(subject);
        context.setSubject(authenticatedUser);
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> properties = new ArrayList<>();

        properties.add(buildProperty(OIDCAuthenticatorConstants.CLIENT_ID, "Client ID", false,
                "Daon TrustX OIDC Client ID.", 0));
        properties.add(buildProperty(OIDCAuthenticatorConstants.CLIENT_SECRET, "Client Secret", true,
                "Daon TrustX OIDC Client Secret.", 1));
        properties.add(buildProperty(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL, "Authorization Endpoint URL",
                false, "Daon TrustX OIDC authorization endpoint URL.", 2));
        properties.add(buildProperty(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, "Token Endpoint URL",
                false, "Daon TrustX OIDC token endpoint URL.", 3));
        properties.add(buildProperty(IdentityApplicationConstants.Authenticator.OIDC.SCOPES, "Scopes", false,
                "OIDC scopes to request from Daon (e.g. openid profile document).", 4));
        properties.add(buildProperty(DAON_LOGIN_PD, "Login Process Definition", false,
                "Daon process definition for verified users (login/auth), as <ProcessDefinitionName:Version>, "
                        + "sent as acr_values.", 5));
        properties.add(buildProperty(DAON_ENROL_PD, "Enrol Process Definition", false,
                "Daon process definition for first-time verification (enrolment/registration), as "
                        + "<ProcessDefinitionName:Version>, sent as acr_values.", 6));
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
     * Reads the IDP claim mappings (WSO2 local claim URI -> Daon remote claim name) from the connection.
     */
    private Map<String, String> getIdpClaimMappings(AuthenticationContext context) {

        Map<String, String> mappings = new HashMap<>();
        ExternalIdPConfig idpConfig = context.getExternalIdP();
        if (idpConfig == null || idpConfig.getClaimMappings() == null) {
            return mappings;
        }
        for (ClaimMapping claimMapping : idpConfig.getClaimMappings()) {
            if (claimMapping.getLocalClaim() != null && claimMapping.getRemoteClaim() != null
                    && StringUtils.isNotBlank(claimMapping.getLocalClaim().getClaimUri())
                    && StringUtils.isNotBlank(claimMapping.getRemoteClaim().getClaimUri())) {
                mappings.put(claimMapping.getLocalClaim().getClaimUri(),
                        claimMapping.getRemoteClaim().getClaimUri());
            }
        }
        return mappings;
    }

    private String getIdpName(AuthenticationContext context) {

        return context.getExternalIdP() != null ? context.getExternalIdP().getIdPName() : null;
    }

    private String buildCallbackUrl(HttpServletRequest request) {
        return request.getScheme() + "://" + request.getServerName() + ":"
                + request.getServerPort() + COMMON_AUTH_ENDPOINT;
    }
}
