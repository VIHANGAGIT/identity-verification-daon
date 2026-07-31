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

package org.wso2.carbon.identity.verification.daon.connector;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ACR_VALUES_PARAM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_ENROL_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_IDP_ID;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_LOGIN_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.LOGIN_HINT;

/**
 * Daon TrustX federated authenticator (login step).
 *
 * <p>Daon is a standard OIDC Authorization Code provider, so the protocol work — building the authorize
 * request (state, nonce, PKCE, scopes, callback URL), exchanging the code for tokens, parsing/validating
 * the ID token and mapping claims — is left entirely to {@link OpenIDConnectAuthenticator}. This class
 * only adds what is Daon-specific:</p>
 * <ul>
 *   <li>resolving the OIDC configuration of a <b>referencing</b> connection from the connection it
 *       references, before the parent builds any request (see {@link #prepareRequest});</li>
 *   <li>the Daon request parameters: the process definition ({@code acr_values}) and the
 *       {@code login_hint} of the enrolled user;</li>
 *   <li>gating login on Daon enrolment, and mapping Daon's error callbacks to user-facing messages.</li>
 * </ul>
 *
 * <p>A connection can be configured in one of two ways, distinguished by whether it sets
 * {@code daon_idp_id}:</p>
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

    private static final String CONFIG_RESOLUTION_ERROR =
            "Could not resolve the Daon OIDC configuration. For a login connection, check the Daon Verifier "
                    + "ID it references; for a Daon Identity Verifier connection, check its own client id "
                    + "and endpoint configuration.";

    @Override
    public String getName() {
        return DaonConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return DaonConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Prepares the Daon-specific parts of the authorize request and hands the request itself to
     * {@link OpenIDConnectAuthenticator#initiateAuthenticationRequest}, which owns the state, nonce,
     * scopes, callback URL and redirect.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                  AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> props = prepareRequest(context);
        if (StringUtils.isBlank(props.get(OIDCAuthenticatorConstants.CLIENT_ID))
                || StringUtils.isBlank(props.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL))) {
            throw new AuthenticationFailedException(CONFIG_RESOLUTION_ERROR);
        }

        // Login only serves users already enrolled with Daon: the association's federated user id is the
        // Daon preferred_username, always sent as login_hint for face re-verification. A user with no
        // Daon association is not enrolled, so the login flow cannot verify them.
        String daonSubject = resolveDaonSubject(context);
        if (StringUtils.isBlank(daonSubject)) {
            // A user with no Daon enrolment cannot be verified at login. The framework drops an
            // AuthenticationFailedException's error code before it reaches the portal, so redirect to the
            // retry page with a stable errorCode the portal switches on, instead of a generic failure.
            redirectToNotEnrolledRetryPage(request, response, context);
            return;
        }
        addDaonQueryParams(props, daonSubject);
        super.initiateAuthenticationRequest(request, response, context);
    }

    /**
     * Surfaces a Daon error callback as a user-facing failure, then lets
     * {@link OpenIDConnectAuthenticator#processAuthenticationResponse} do the token exchange, ID token
     * handling and subject/claim resolution.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                  AuthenticationContext context)
            throws AuthenticationFailedException {

        // Daon can return a standard OAuth2 error (in place of a code) when the user cancels/declines the
        // verification or Daon fails. Handle it before the parent tries to read a code off the callback;
        // log the raw values so Daon's specific verification-failure codes can be mapped later if needed.
        String error = request.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR);
        if (StringUtils.isNotBlank(error)) {
            String errorDescription = request.getParameter(DaonConstants.OAUTH2_ERROR_DESCRIPTION);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Daon returned an error on the login callback. error=" + error
                        + ", error_description=" + errorDescription);
            }
            throw new AuthenticationFailedException(
                    DaonCallbackErrors.resolveUserFacingMessage(error, errorDescription));
        }

        // The framework repopulates the authenticator properties from the connection on every request, so
        // a referencing connection's OIDC credentials/token endpoint are resolved again for the callback.
        Map<String, String> props = prepareRequest(context);
        if (StringUtils.isBlank(props.get(OIDCAuthenticatorConstants.CLIENT_ID))
                || StringUtils.isBlank(props.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL))) {
            throw new AuthenticationFailedException(CONFIG_RESOLUTION_ERROR);
        }
        super.processAuthenticationResponse(request, response, context);
    }

    /**
     * Daon identifies the verified user by {@code preferred_username} (the value recorded in the
     * federated association and sent back as {@code login_hint}), so that claim is the authenticated
     * subject; the standard {@code sub} claim is the fallback.
     */
    @Override
    protected String getAuthenticateUser(AuthenticationContext context, Map<String, Object> oidcClaims,
                                         OAuthClientResponse oidcResponse) {

        Object preferredUsername = oidcClaims.get(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM);
        if (preferredUsername != null && StringUtils.isNotBlank(preferredUsername.toString())) {
            return preferredUsername.toString();
        }
        return super.getAuthenticateUser(context, oidcClaims, oidcResponse);
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
     * Resolves the authenticator properties the parent should act on and sets them back on the context: a
     * referencing login connection's OIDC credentials, endpoints and scopes come from the referenced Daon
     * Identity Verifier connection, a self-contained connection's from its own config. The parent then
     * reads a fully configured OIDC connection either way.
     */
    private Map<String, String> prepareRequest(AuthenticationContext context) {

        Map<String, String> props = DaonReferencedIdpUtil.buildEffectiveProperties(
                context.getAuthenticatorProperties(), context.getTenantDomain());
        context.setAuthenticatorProperties(props);
        return props;
    }

    /**
     * Adds the Daon request parameters — the login process definition as {@code acr_values} and the
     * enrolled user's Daon {@code preferred_username} as {@code login_hint} — to the connection's
     * additional query parameters, which is where {@link OpenIDConnectAuthenticator} picks up anything
     * beyond the standard OIDC parameters. Values are appended raw; the parent URL-encodes them.
     */
    private void addDaonQueryParams(Map<String, String> props, String daonSubject) {

        StringBuilder queryParams = new StringBuilder();
        String configuredQueryParams = props.get(FrameworkConstants.QUERY_PARAMS);
        if (StringUtils.isNotBlank(configuredQueryParams)) {
            queryParams.append(configuredQueryParams).append("&");
        }
        String processDefinition = props.get(DAON_LOGIN_PD);
        if (StringUtils.isNotBlank(processDefinition)) {
            queryParams.append(ACR_VALUES_PARAM).append("=").append(processDefinition).append("&");
        }
        queryParams.append(LOGIN_HINT).append("=").append(daonSubject);
        props.put(FrameworkConstants.QUERY_PARAMS, queryParams.toString());
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

    /**
     * Sends a user who is not enrolled with Daon to the authentication retry page with a dedicated
     * "not enrolled" message, via {@link FrameworkUtils#sendToRetryPage}. That framework helper sets up
     * the error cache / branding / layout context the retry page needs (a hand-built redirect renders a
     * blank page). The status/message are passed as i18n keys the retry page resolves, so no raw text is
     * hard-coded in the flow and the message stays localizable.
     */
    private void redirectToNotEnrolledRetryPage(HttpServletRequest request, HttpServletResponse response,
                                                AuthenticationContext context)
            throws AuthenticationFailedException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("User not enrolled with Daon TrustX at the login step; sending to the retry page "
                    + "with status message key: " + DaonConstants.NOT_ENROLLED_RETRY_STATUS_MSG);
        }
        try {
            FrameworkUtils.sendToRetryPage(request, response, context,
                    DaonConstants.NOT_ENROLLED_RETRY_STATUS,
                    DaonConstants.NOT_ENROLLED_RETRY_STATUS_MSG);
            context.setCurrentAuthenticator(getName());
        } catch (IOException e) {
            LOG.error("Failed to redirect the not-enrolled user to the Daon login retry page.", e);
            throw new AuthenticationFailedException(
                    DaonConstants.USER_NOT_ENROLLED_ERROR_CODE,
                    "The user is not enrolled with Daon TrustX.");
        }
    }
}
