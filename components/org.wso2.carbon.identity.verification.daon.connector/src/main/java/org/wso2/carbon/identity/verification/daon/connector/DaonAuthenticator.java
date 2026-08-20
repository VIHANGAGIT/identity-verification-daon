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
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;
import org.wso2.carbon.identity.verification.daon.connector.internal.DaonConnectorDataHolder;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonCallbackErrors;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonClaimsRequestBuilder;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonFederatedAssociationUtil;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonJwtUtil;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonReferencedIdpUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
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
 * only adds what is Daon-specific.</p>
 */
public class DaonAuthenticator extends OpenIDConnectAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = 1L;
    private static final Log LOG = LogFactory.getLog(DaonAuthenticator.class);

    /**
     * Fallback heading for a Daon failure on the retry page, used for the errors that carry no i18n key of
     * their own (the administrator-facing ones). Errors that have one send it instead — see
     * {@link #resolveRetryPageStatus}.
     */
    private static final String RETRY_PAGE_STATUS_KEY = "unable.to.proceed";

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
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_OIDC_CONFIG_NOT_RESOLVED, "authorization"));
            failRequest(request, response, context, ErrorMessage.ERROR_OIDC_CONFIG_NOT_RESOLVED);
            return;
        }

        // The association's federated user id is the Daon preferred_username, sent as login_hint for face
        // re-verification. Its absence means the user is not enrolled and there is nothing to verify
        // against; its presence means they are, and the step must not do anything but re-verify.
        String daonSubject = resolveDaonSubject(context);
        Map<String, String> runtimeParams = getRuntimeParams(context);
        if (LOG.isDebugEnabled()) {
            // An adaptive script addresses these per connection name, so a name that does not match this
            // connection delivers nothing and the step silently behaves as an unscripted one. An empty map
            // here when a script set parameters is that mismatch.
            LOG.debug("Daon login step. Enrolled: " + (daonSubject != null)
                    + ", usable login_hint: " + StringUtils.isNotBlank(daonSubject)
                    + ", runtime parameters from the adaptive script: " + runtimeParams.keySet());
        }

        if (Boolean.parseBoolean(runtimeParams.get(DaonConstants.DAON_RUNTIME_PARAM_ENROL))) {
            // Any non-null value means an association exists, blank included: getAssociatedDaonSubject
            // returns the empty string for an association whose federated user id is unset. Testing for
            // "not blank" here would let such an account past this guard and enrol a second identity for
            // it, which is exactly what the guard exists to prevent — so the test is "not null".
            if (daonSubject != null) {
                // SECURITY: never enrol an account that already has an enrolment. Re-verification and
                // enrolment are mutually exclusive by account state, decided here from the association
                // store and not by the script that asked. Without this, someone holding the account's
                // first-factor credentials but not its enrolled identity would only have to fail the face
                // verification to be routed here and bind their own identity to the account.
                LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_ALREADY_ENROLLED,
                        resolveDaonIdpName(context)));
                failRequest(request, response, context, ErrorMessage.ERROR_ALREADY_ENROLLED);
                return;
            }
            initiateEnrolmentRequest(request, response, context, props);
            return;
        }
        if (StringUtils.isBlank(daonSubject)) {
            // Fail the step rather than ending the flow at the retry page: only a failed step reaches an
            // adaptive script's onFail handler, which is what routes the user into enrolment.
            // sendToRetryPage writes a redirect and returns, leaving the script nothing to act on.
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_USER_NOT_ENROLLED, "login"));
            failRequest(request, response, context, ErrorMessage.ERROR_USER_NOT_ENROLLED);
            return;
        }
        // Remember the identity this request is asking Daon to verify, so the callback can be bound to it.
        context.setProperty(DaonConstants.DAON_EXPECTED_SUBJECT, daonSubject);
        addDaonQueryParams(props, props.get(DAON_LOGIN_PD), daonSubject, null);
        super.initiateAuthenticationRequest(request, response, context);
    }

    /**
     * Runs the referenced Daon Identity Verifier's <b>enrol</b> process definition for a user who has no
     * Daon enrolment, and marks the request so the callback records the resulting identity.
     *
     * <p>Only reached for a user the association store confirms is not enrolled (see
     * the caller). No {@code login_hint} is sent — there is no enrolled identity to
     * hint at — and the user's known attributes go instead as OIDC claim value-requests, exactly as the
     * invited-user enrolment flow does, so Daon validates the presented document against the profile the
     * account already has rather than enrolling whoever completes the verification.</p>
     *
     * <p>An enrolment that cannot be made to prove that much is not attempted: the step fails and the
     * reason is logged with its code, rather than binding an identity on weaker evidence than the
     * registration flows demand.</p>
     */
    private void initiateEnrolmentRequest(HttpServletRequest request, HttpServletResponse response,
                                          AuthenticationContext context, Map<String, String> props)
            throws AuthenticationFailedException {

        // Resolved from the referenced Daon Identity Verifier connection, where the enrol PD is configured
        // alongside the OIDC credentials (or from this connection's own props if it is self-contained).
        String enrolProcessDefinition = props.get(DAON_ENROL_PD);
        if (StringUtils.isBlank(enrolProcessDefinition)) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_ENROL_PD_NOT_CONFIGURED));
            failRequest(request, response, context, ErrorMessage.ERROR_ENROL_PD_NOT_CONFIGURED);
            return;
        }
        AuthenticatedUser authenticatedUser = context.getLastAuthenticatedUser();
        String qualifiedUsername = resolveQualifiedUsername(authenticatedUser);
        if (StringUtils.isBlank(qualifiedUsername)) {
            // Nothing to enrol, and nothing for the callback to bind the verified identity to.
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_PERSISTING_FED_ASSOCIATION,
                    "the authenticating user could not be resolved at the login step"));
            failRequest(request, response, context, ErrorMessage.ERROR_USER_NOT_ENROLLED);
            return;
        }

        Map<String, String> claimMappings = resolveClaimMappings(context);
        Map<String, String> valueRequests =
                resolveValueRequests(context, authenticatedUser, qualifiedUsername, claimMappings);
        if (!DaonClaimsRequestBuilder.hasDocumentVerifiableValue(valueRequests)) {
            // With no document-verifiable attribute Daon has nothing to compare the document against, so a
            // successful verification would prove only that some valid document was presented — not enough
            // to bind an identity to this account.
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_NO_VERIFIABLE_CLAIM_VALUES, "enrolment"));
            // Which half is missing decides the fix — attribute mappings on the connection, or the values
            // on the user's profile — and the two are indistinguishable from the message above.
            LOG.error("Daon enrolment could not be attempted: " + claimMappings.size() + " attribute "
                    + "mapping(s) resolved (Daon claims: " + claimMappings.values() + "), of which "
                    + valueRequests.size() + " had a value on the user's profile (Daon claims: "
                    + valueRequests.keySet() + "). At least one of given_name, family_name, "
                    + "family_name_and_given_name, birthdate, document_number or document_personal_number "
                    + "must be mapped and populated.");
            failRequest(request, response, context, ErrorMessage.ERROR_NO_VERIFIABLE_CLAIM_VALUES);
            return;
        }
        String claimsRequest;
        try {
            claimsRequest = DaonClaimsRequestBuilder.buildClaimsParam(
                    new ArrayList<>(claimMappings.values()), valueRequests);
        } catch (DaonServerException e) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_BUILDING_CLAIMS_REQUEST), e);
            failRequest(request, response, context, ErrorMessage.ERROR_BUILDING_CLAIMS_REQUEST);
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Enrolling a user with no Daon enrolment at the login step, using the enrol process "
                    + "definition: " + enrolProcessDefinition);
        }
        // Marks the in-flight request as an enrolment, and carries the local user (and the tenant it lives
        // in) that the callback binds the verified identity to.
        context.setProperty(DaonConstants.DAON_ENROLLING_USER, qualifiedUsername);
        context.setProperty(DaonConstants.DAON_ENROLLING_USER_TENANT,
                resolveUserTenantDomain(authenticatedUser, context));
        addDaonQueryParams(props, enrolProcessDefinition, null, claimsRequest);
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
        // verification or Daon fails. Handle it before the parent tries to read a code off the callback.
        String error = request.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR);
        if (StringUtils.isNotBlank(error)) {
            String errorDescription = request.getParameter(DaonConstants.OAUTH2_ERROR_DESCRIPTION);
            ErrorMessage callbackError = DaonCallbackErrors.resolveError(error, errorDescription);
            if (LOG.isDebugEnabled()) {
                LOG.debug(callbackError.getCode() + " - Daon returned an error on the login callback. error="
                        + error + ", error_description=" + errorDescription);
            }
            // The framework drops the error code before the portal renders, so the code here serves the
            // server log; the user sees the catalogue's message.
            throw failCallback(context, callbackError);
        }

        // The framework repopulates the authenticator properties from the connection on every request, so
        // a referencing connection's OIDC credentials/token endpoint are resolved again for the callback.
        Map<String, String> props = prepareRequest(context);
        if (StringUtils.isBlank(props.get(OIDCAuthenticatorConstants.CLIENT_ID))
                || StringUtils.isBlank(props.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL))) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_OIDC_CONFIG_NOT_RESOLVED, "token"));
            throw failCallback(context, ErrorMessage.ERROR_OIDC_CONFIG_NOT_RESOLVED);
        }
        super.processAuthenticationResponse(request, response, context);
        // Consume the in-flight request's markers here, before either branch runs. They describe *this*
        // authorize request, and the authentication context outlives it: a second Daon step in the same
        // sequence (a script that enrols and then re-verifies, or a step retry) would otherwise read the
        // previous request's marker, take the enrolment branch again, and skip the identity binding check
        // below — failing a legitimate login with DAON-60010 because the subject is already enrolled to
        // the very user being logged in.
        String enrollingUser = (String) context.getProperty(DaonConstants.DAON_ENROLLING_USER);
        String enrollingUserTenant = (String) context.getProperty(DaonConstants.DAON_ENROLLING_USER_TENANT);
        String expectedSubject = (String) context.getProperty(DaonConstants.DAON_EXPECTED_SUBJECT);
        context.removeProperty(DaonConstants.DAON_ENROLLING_USER);
        context.removeProperty(DaonConstants.DAON_ENROLLING_USER_TENANT);
        context.removeProperty(DaonConstants.DAON_EXPECTED_SUBJECT);

        if (StringUtils.isNotBlank(enrollingUser)) {
            // An enrolment: there is no recorded identity to match against — this callback is what creates
            // it. Daon has already validated the document against the user's profile, via the claim
            // value-requests the authorize request carried.
            persistEnrolment(context, enrollingUser, enrollingUserTenant);
            return;
        }
        assertVerifiedIdentityMatchesUser(context, expectedSubject);
    }

    /**
     * Records the identity Daon just verified as the enrolment of the local user the request was built for,
     * so later logins re-verify against it — the same federated association the registration and
     * invited-user flows write via {@link DaonFederatedAssociationListener}.
     *
     * <p>Fails the step rather than logging the user in whenever the enrolment cannot be recorded: no
     * identity returned, the IDP name unresolvable, the identity already enrolled for another account, or
     * the write itself failing. A login that silently skipped the enrolment would leave the account looking
     * not-enrolled at the next attempt, with nothing to explain why.</p>
     *
     * @param qualifiedUsername the local user to bind the verified identity to, stashed when the request
     *                          was built.
     * @param userTenantDomain  the tenant that user lives in, stashed alongside it. The association is
     *                          keyed on (username, userstore domain, tenant), so this must be the same
     *                          tenant {@link #resolveDaonSubject} reads back with — the user's, which in a
     *                          B2B/organization login is not the context's (the service provider's).
     */
    private void persistEnrolment(AuthenticationContext context, String qualifiedUsername,
                                  String userTenantDomain)
            throws AuthenticationFailedException {

        String tenantDomain = StringUtils.isNotBlank(userTenantDomain)
                ? userTenantDomain : context.getTenantDomain();

        // preferred_username is the identifier Daon issues for the enrolled person, and the value both the
        // enrolment flows record and the login step later compares against, so it is the one recorded here.
        String daonSubject = getClaimValue(context.getSubject(), DaonConstants.JWT_PREFERRED_USERNAME_CLAIM);
        if (StringUtils.isBlank(daonSubject)) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_ENROLMENT_IDENTITY_NOT_RETURNED));
            throw failCallback(context, ErrorMessage.ERROR_ENROLMENT_IDENTITY_NOT_RETURNED);
        }
        String daonIdpName = resolveDaonIdpName(context);
        if (StringUtils.isBlank(daonIdpName)) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_PERSISTING_FED_ASSOCIATION,
                    "the Daon IDP name could not be resolved at the enrolment callback"));
            throw failCallback(context, ErrorMessage.ERROR_CREATING_FED_ASSOCIATION);
        }
        // The enrolling user had no association when the request was built, so a Daon subject that already
        // resolves to a local user resolves to a different one.
        String existingUser = DaonFederatedAssociationUtil.getLocalUserForDaonSubject(
                tenantDomain, daonIdpName, daonSubject);
        if (StringUtils.isNotBlank(existingUser)) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_DAON_IDENTITY_ALREADY_ENROLLED,
                    daonIdpName));
            throw failCallback(context, ErrorMessage.ERROR_DAON_IDENTITY_ALREADY_ENROLLED);
        }
        User associationUser =
                DaonFederatedAssociationUtil.buildUser(qualifiedUsername, tenantDomain);
        if (!DaonFederatedAssociationUtil.createAssociation(associationUser, daonIdpName, daonSubject)) {
            // The util has already logged the specific cause with its own code. The store enforces
            // uniqueness on (IDP, Daon subject), so this also catches an identity claimed by another
            // account between the lookup above and this write.
            throw failCallback(context, ErrorMessage.ERROR_CREATING_FED_ASSOCIATION);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Recorded the Daon enrolment performed at the login step, for IDP: " + daonIdpName);
        }
    }

    /**
     * Binds the identity Daon verified back to the user this login step is running for.
     *
     * <p>{@code login_hint} is only a hint per OIDC — Daon verifies whoever actually presents themselves —
     * so without this check anyone who completes a Daon verification with their own enrolled account
     * satisfies the verification step for any other user's login. The authentication framework does not
     * compare a federated step's subject with the already-identified local user, so the check has to live
     * here (the password-recovery flow does the equivalent in {@link DaonExecutor}).</p>
     *
     * <p>Runs after the parent has exchanged the code and resolved the subject, since that is what makes
     * the ID token's identity claims available. Throwing here fails the step, so the sequence never
     * completes with an unbound verification.</p>
     */
    private void assertVerifiedIdentityMatchesUser(AuthenticationContext context, String expectedSubject)
            throws AuthenticationFailedException {

        // Compare the preferred_username claim itself rather than the framework's subject identifier: the
        // two are normally the same value (see getAuthenticateUser), but a connection configured with a
        // UserIdClaimUri makes the parent resolve the subject identifier from that claim instead, while the
        // expected subject is always the preferred_username recorded in the association at enrolment.
        String preferredUsername =
                getClaimValue(context.getSubject(), DaonConstants.JWT_PREFERRED_USERNAME_CLAIM);

        if (DaonJwtUtil.isExpectedSubject(expectedSubject, preferredUsername)) {
            return;
        }
        if (LOG.isDebugEnabled()) {
            // A blank expected subject reaches here too (the context property was lost, so the binding
            // cannot be proven): both cases fail closed, and only the log line tells them apart.
            LOG.debug(ErrorMessage.ERROR_LOGIN_IDENTITY_MISMATCH.getCode()
                    + " - Daon verified an identity that does not match the authenticating user. Expected: "
                    + expectedSubject + ", returned preferred_username: " + preferredUsername);
        }
        LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_LOGIN_IDENTITY_MISMATCH));
        throw failCallback(context, ErrorMessage.ERROR_LOGIN_IDENTITY_MISMATCH);
    }

    /**
     * Reads a single ID token claim off the authenticated user's attributes. The parent maps every ID
     * token claim it does not filter out into these attributes, keyed by a {@link ClaimMapping} whose
     * local and remote claim URIs are both the raw claim name at this point.
     */
    private String getClaimValue(AuthenticatedUser user, String claimName) {

        if (user == null || user.getUserAttributes() == null) {
            return null;
        }
        for (Map.Entry<ClaimMapping, String> entry : user.getUserAttributes().entrySet()) {
            ClaimMapping mapping = entry.getKey();
            if (mapping == null) {
                continue;
            }
            if (mapping.getLocalClaim() != null
                    && claimName.equals(mapping.getLocalClaim().getClaimUri())) {
                return entry.getValue();
            }
            if (mapping.getRemoteClaim() != null
                    && claimName.equals(mapping.getRemoteClaim().getClaimUri())) {
                return entry.getValue();
            }
        }
        return null;
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
     * Adds the Daon request parameters to the connection's additional query parameters, which is where
     * {@link OpenIDConnectAuthenticator} picks up anything beyond the standard OIDC parameters: the process
     * definition as {@code acr_values}, plus either the enrolled user's Daon {@code preferred_username} as
     * {@code login_hint} (re-verification) or the {@code claims} request (enrolment). Blank values are
     * skipped. Values are appended raw; the parent URL-encodes them.
     */
    private void addDaonQueryParams(Map<String, String> props, String processDefinition, String loginHint,
                                    String claimsRequest) {

        List<String> queryParams = new ArrayList<>();
        String configuredQueryParams = props.get(FrameworkConstants.QUERY_PARAMS);
        if (StringUtils.isNotBlank(configuredQueryParams)) {
            queryParams.add(configuredQueryParams);
        }
        if (StringUtils.isNotBlank(processDefinition)) {
            queryParams.add(ACR_VALUES_PARAM + "=" + processDefinition);
        }
        if (StringUtils.isNotBlank(loginHint)) {
            queryParams.add(LOGIN_HINT + "=" + loginHint);
        }
        if (StringUtils.isNotBlank(claimsRequest)) {
            queryParams.add(DaonConstants.CLAIMS_PARAM + "=" + claimsRequest);
        }
        props.put(FrameworkConstants.QUERY_PARAMS, String.join("&", queryParams));
    }

    /**
     * Reads the claim mappings (WSO2 local claim URI -&gt; Daon claim name) that name the attributes an
     * enrolment can ask Daon to verify the document against.
     *
     * <p>This connection's own mappings win. A login connection that has none falls back to the
     * <b>referenced</b> Daon Identity Verifier's — enrolment is otherwise driven entirely by that
     * connection, so its Attributes tab is the natural place to have mapped the Daon claims.</p>
     */
    private Map<String, String> resolveClaimMappings(AuthenticationContext context) {

        Map<String, String> mappings = readClaimMappings(
                context.getExternalIdP() != null ? context.getExternalIdP().getClaimMappings() : null);
        if (!mappings.isEmpty()) {
            return mappings;
        }
        String idpResourceId = context.getAuthenticatorProperties().get(DAON_IDP_ID);
        if (StringUtils.isBlank(idpResourceId)) {
            return mappings;
        }
        mappings = DaonReferencedIdpUtil.resolveClaimMappings(idpResourceId, context.getTenantDomain());
        if (LOG.isDebugEnabled()) {
            LOG.debug("The login connection has no attribute mappings of its own; using the "
                    + mappings.size() + " mapping(s) of the referenced Daon Identity Verifier for the "
                    + "enrolment claim value-requests.");
        }
        return mappings;
    }

    /** Flattens an IDP claim mapping array into local claim URI -&gt; Daon claim name. */
    private Map<String, String> readClaimMappings(ClaimMapping[] claimMappings) {

        Map<String, String> mappings = new HashMap<>();
        if (claimMappings == null) {
            return mappings;
        }
        for (ClaimMapping claimMapping : claimMappings) {
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
        return mappings;
    }

    /**
     * Resolves the values an enrolment sends to Daon as OIDC claim value-requests: the mapped attributes
     * the account already holds, keyed by Daon claim name.
     *
     * <p>Values come from the claims the preceding step already resolved for the user where present, and
     * from the user store for the rest. A value that cannot survive the query string as-is is dropped
     * rather than sent broken: {@link OpenIDConnectAuthenticator} splits the additional query parameters on
     * {@code &} and {@code =} before re-encoding them, so a value containing either would truncate the
     * {@code claims} parameter. Dropping one cannot weaken the check silently — the caller still requires a
     * document-verifiable value to remain.</p>
     */
    private Map<String, String> resolveValueRequests(AuthenticationContext context,
                                                     AuthenticatedUser authenticatedUser,
                                                     String qualifiedUsername,
                                                     Map<String, String> claimMappings) {

        if (claimMappings.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, String> localValues = new HashMap<>();
        List<String> unresolved = new ArrayList<>();
        for (String localClaimUri : claimMappings.keySet()) {
            String value = getClaimValue(authenticatedUser, localClaimUri);
            if (StringUtils.isNotBlank(value)) {
                localValues.put(localClaimUri, value);
            } else {
                unresolved.add(localClaimUri);
            }
        }
        if (!unresolved.isEmpty()) {
            localValues.putAll(readStoredClaims(context.getTenantDomain(), qualifiedUsername, unresolved));
        }

        Map<String, String> valuesByDaonClaimName = new HashMap<>();
        for (Map.Entry<String, String> mapping : claimMappings.entrySet()) {
            String value = localValues.get(mapping.getKey());
            if (StringUtils.isBlank(value)) {
                continue;
            }
            value = value.trim();
            if (value.contains("&") || value.contains("=")) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Skipping the Daon claim value-request for '" + mapping.getValue()
                            + "': the value contains a character the authorization request's additional "
                            + "query parameters cannot carry.");
                }
                continue;
            }
            valuesByDaonClaimName.put(mapping.getValue(), value);
        }
        return valuesByDaonClaimName;
    }

    /**
     * Reads the given local claims of the user being enrolled from the user store. Returns whatever could
     * be read: a failure simply leaves those value-requests out, and the caller still refuses to enrol
     * without a document-verifiable value.
     */
    private Map<String, String> readStoredClaims(String tenantDomain, String qualifiedUsername,
                                                 List<String> claimUris) {

        Map<String, String> values = new HashMap<>();
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            UserStoreManager userStoreManager = DaonConnectorDataHolder.getRealmService()
                    .getTenantUserRealm(tenantId).getUserStoreManager();
            Map<String, String> storedClaims = userStoreManager.getUserClaimValues(qualifiedUsername,
                    claimUris.toArray(new String[0]), null);
            if (storedClaims != null) {
                for (Map.Entry<String, String> claim : storedClaims.entrySet()) {
                    if (StringUtils.isNotBlank(claim.getValue())) {
                        values.put(claim.getKey(), claim.getValue());
                    }
                }
            }
        } catch (UserStoreException e) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_READING_USER_CLAIMS_AT_LOGIN), e);
        }
        return values;
    }

    /**
     * Rebuilds the identified user's domain-qualified username the way {@link DaonFederatedAssociationUtil}
     * stores it (bare username + user store domain), so an association written by an enrolment is found by
     * the enrolment lookup on the next login.
     */
    private String resolveQualifiedUsername(AuthenticatedUser authenticatedUser) {

        if (authenticatedUser == null || StringUtils.isBlank(authenticatedUser.getUserName())) {
            return null;
        }
        String username = UserCoreUtil.removeDomainFromName(authenticatedUser.getUserName());
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        if (StringUtils.isNotBlank(userStoreDomain)) {
            username = userStoreDomain + "/" + username;
        }
        return username;
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
            // Distinguished from a genuine "not enrolled" outcome: all of these return null and end up on
            // the same retry page, so the log line is the only way to tell them apart afterwards.
            LOG.debug("No last authenticated user in the context; cannot resolve the Daon subject.");
            return null;
        }
        String daonIdpName = resolveDaonIdpName(context);
        if (StringUtils.isBlank(daonIdpName)) {
            LOG.debug("Could not resolve the Daon IDP name; cannot resolve the Daon subject.");
            return null;
        }
        String username = resolveQualifiedUsername(authenticatedUser);
        if (StringUtils.isBlank(username)) {
            LOG.debug("The last authenticated user carries no username; cannot resolve the Daon subject.");
            return null;
        }
        User associationUser = DaonFederatedAssociationUtil.buildUser(username,
                resolveUserTenantDomain(authenticatedUser, context));
        return DaonFederatedAssociationUtil.getAssociatedDaonSubject(associationUser, daonIdpName);
    }

    /**
     * The tenant domain the identified local user's federated association is keyed on.
     *
     * <p>The user's own tenant, not the authentication context's. The two are the same for an ordinary
     * login, but in a B2B/organization login the context carries the service provider's tenant while the
     * user lives in another — and every read and write of the association has to agree on one of them, or
     * an enrolment recorded under one tenant is invisible to the lookup under the other and the account
     * looks permanently not-enrolled. The context's tenant is only a fallback for a user that carries
     * none.</p>
     */
    private String resolveUserTenantDomain(AuthenticatedUser authenticatedUser,
                                           AuthenticationContext context) {

        if (authenticatedUser != null && StringUtils.isNotBlank(authenticatedUser.getTenantDomain())) {
            return authenticatedUser.getTenantDomain();
        }
        return context.getTenantDomain();
    }

    /**
     * Resolves the Daon IDP name the federated association is keyed on: the referenced Identity
     * Verification connection's name when {@code daon_idp_id} is set (login connection), otherwise this
     * connection's own name (self-contained connection).
     */
    private String resolveDaonIdpName(AuthenticationContext context) {

        String idpResourceId = context.getAuthenticatorProperties().get(DAON_IDP_ID);
        if (StringUtils.isNotBlank(idpResourceId)) {
            String referencedIdpName =
                    DaonReferencedIdpUtil.resolveIdpName(idpResourceId, context.getTenantDomain());
            if (StringUtils.isBlank(referencedIdpName)) {
                // Infrastructure or configuration failure, not an enrolment problem — DaonReferencedIdpUtil
                // has already logged the specific cause with its own code.
                LOG.debug("Could not resolve the referenced Daon IDP name for resource id: " + idpResourceId);
            }
            return referencedIdpName;
        }
        if (context.getExternalIdP() == null) {
            LOG.debug("No external IDP in the authentication context; cannot resolve the Daon IDP name.");
            return null;
        }
        return context.getExternalIdP().getIdPName();
    }

    /**
     * Records the Daon failure on the context so the framework surfaces it instead of its generic
     * "something went wrong during authentication".
     *
     * <p>{@code DefaultAuthenticationRequestHandler#populateErrorInformation} copies these onto the
     * authentication result for <b>any</b> unauthenticated outcome, not just a script's {@code fail()},
     * and the OAuth layer turns them into {@code error} / {@code error_description} on the redirect back
     * to the application. This is what carries the {@code DAON-} code out of the server, since an
     * {@link AuthenticationFailedException}'s own code is dropped before the portal renders.</p>
     *
     * <p>That applies only where the step <b>throws</b>: a script-driven request failure, and every
     * callback failure ({@link #failCallback}). On the retry-page leg of {@link #failRequest} the redirect
     * ends the flow at the retry page, so no authentication result is ever built, nothing reads these
     * properties, and the application is not redirected to at all. On that leg the code reaches the server
     * log only — what the user sees is the i18n wording {@link #failRequest} sends.</p>
     *
     * <p>Nothing is named for the login page's error banner. When the framework sends the user back to a
     * multi-option step, that banner's text comes from {@code authFailureMsg}, which the authentication
     * portal renders only for keys in its own resource bundle — it carries no identity verification entry,
     * and the {@code IdentityErrorMsgContext} hook that would set one is itself inert unless
     * {@code showAuthFailureReason} is enabled on the server. The user-facing channels that do work are the
     * retry page (see {@link #failRequest}) and the error the application receives.</p>
     */
    private void setErrorInformation(AuthenticationContext context, ErrorMessage error) {

        context.setProperty(FrameworkConstants.AUTH_ERROR_CODE, error.getCode());
        context.setProperty(FrameworkConstants.AUTH_ERROR_MSG, error.getMessage());
    }

    /**
     * Whether an adaptive script is driving this sequence, and so whether a failed step will be offered
     * to an {@code onFail} handler that may route the user somewhere else (enrolment, typically).
     */
    private boolean isAdaptiveScriptDriven(AuthenticationContext context) {

        return context.getSequenceConfig() != null
                && context.getSequenceConfig().getAuthenticationGraph() != null
                && context.getSequenceConfig().getAuthenticationGraph().isEnabled();
    }

    /**
     * Ends the step on a failure raised while <b>building</b> the Daon request, using whichever channel
     * the flow can actually act on.
     *
     * <p>With an adaptive script attached the step is failed, because only a failed step reaches an
     * {@code onFail} handler — that is what lets a script route a not-enrolled user into enrolment.
     * Without one, nothing would render the reason: the framework drops the exception's code and shows a
     * generic message, so the wording is put on the retry page directly. Both paths record the error on the
     * context, but only the script-driven one has anything that reads it: this leg's redirect ends the flow
     * at the retry page, so no authentication result is built and the application is never redirected to.
     * The {@code DAON-} code therefore reaches the server log only.</p>
     *
     * <p>The retry page's two slots carry the same pair of {@code {{key}}} i18n tokens the registration and
     * recovery flows send — {@link DaonErrorConstants.ErrorMessage#getUserMessageToken()} as the status and
     * {@link DaonErrorConstants.ErrorMessage#getUserDescriptionToken()} as the status message — so the
     * login step's wording is localized from the same bundle entries as the flow portal's.</p>
     *
     * <p>Both slots go through {@code AuthenticationEndpointUtil.customi18n}, which is a plain
     * {@code ResourceBundle.getString} that returns its input HTML-escaped when the key is missing and does
     * <b>not</b> strip the {@code {{ }}} wrapping. The authentication endpoint's bundle therefore needs a
     * {@code {{<i18nKey>.message}}} and {@code {{<i18nKey>.description}}} entry — braces included — for
     * each keyed error, or the token renders literally.</p>
     *
     * <p>Only safe on the request-building leg. On the callback leg the parent treats a normal return as a
     * successful authentication, so failures there must throw — see {@link #failCallback}.</p>
     */
    private void failRequest(HttpServletRequest request, HttpServletResponse response,
                             AuthenticationContext context, ErrorMessage error)
            throws AuthenticationFailedException {

        setErrorInformation(context, error);
        if (isAdaptiveScriptDriven(context)) {
            throw DaonExceptionMgt.handleAuthFailedException(error);
        }
        try {
            FrameworkUtils.sendToRetryPage(request, response, context, resolveRetryPageStatus(error),
                    DaonExceptionMgt.userDescription(error));
            context.setCurrentAuthenticator(getName());
        } catch (IOException e) {
            LOG.error(DaonExceptionMgt.errorLog(error), e);
            throw DaonExceptionMgt.handleAuthFailedException(error, e);
        }
    }

    /**
     * The retry page status for an error: its own i18n message token when it has one, otherwise the generic
     * heading.
     *
     * <p>The fallback is not cosmetic. The keyless errors are the administrator-facing ones, and
     * {@link DaonExceptionMgt#userDescription} already falls back to their plain message for the status
     * message slot — sending that same sentence as the status too would render it twice, as both the
     * heading and the body.</p>
     */
    private String resolveRetryPageStatus(ErrorMessage error) {

        return error.getUserMessageToken() != null ? error.getUserMessageToken() : RETRY_PAGE_STATUS_KEY;
    }

    /**
     * Builds the exception for a failure raised while <b>processing</b> the Daon callback, recording the
     * error on the context first so the application still receives the Daon code and message.
     *
     * <p>These always throw: returning normally from {@code processAuthenticationResponse} tells the parent
     * the step succeeded, so the retry page cannot be used here.</p>
     */
    private AuthenticationFailedException failCallback(AuthenticationContext context, ErrorMessage error) {

        setErrorInformation(context, error);
        return DaonExceptionMgt.handleAuthFailedException(error);
    }
}
