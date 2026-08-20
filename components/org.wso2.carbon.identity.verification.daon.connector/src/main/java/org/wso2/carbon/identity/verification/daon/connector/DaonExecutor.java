/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.verification.daon.connector;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectExecutor;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.metadata.FlowExecutorMetadata;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.flow.mgt.Constants.ExecutorBehaviorFlags;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonException;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;
import org.wso2.carbon.identity.verification.daon.connector.internal.DaonConnectorDataHolder;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonCallbackErrors;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonClaimsRequestBuilder;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonFederatedAssociationUtil;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonJwtUtil;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonReferencedIdpUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ACR_VALUES_PARAM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIMS_PARAM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_CLAIMS_REQUEST;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_ENROL_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_FED_IDP_NAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_FED_SUBJECT;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_IDP_ID;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_LOGIN_HINT;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_LOGIN_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_SELECTED_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.FLOW_TYPE_INVITED_USER_REGISTRATION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.FLOW_TYPE_PASSWORD_RECOVERY;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.FLOW_TYPE_REGISTRATION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.LOGIN_HINT;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.OAUTH2_ERROR_DESCRIPTION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.WSO2_GIVENNAME_CLAIM_URI;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.WSO2_LASTNAME_CLAIM_URI;

/**
 * Flow executor for the Daon TrustX identity provider (IDP).
 *
 * <p>Drives the OIDC authorization-code flow against Daon for the registration, invited-user, and
 * password-recovery flows. Daon is a standard federated OIDC connection, so client credentials,
 * endpoints and scope resolve natively from the connection's authenticator config; claim mappings
 * come from the IDP claim configuration.</p>
 *
 * <p>The returned ID token carries a nested {@code verifiedClaims.claims} object with the verified
 * identity attributes. For self-registration these provision the new user's profile; for invited
 * users they are validated against the pre-populated profile. On success a federated association
 * (local user &lt;-&gt; Daon {@code preferred_username}) is recorded via
 * {@link DaonFederatedAssociationListener}; its presence marks the user as Daon-verified and supplies
 * the {@code login_hint} for later face-auth. No custom user claims are used.</p>
 */
public class DaonExecutor extends OpenIDConnectExecutor {

    private static final Log LOG = LogFactory.getLog(DaonExecutor.class);
    private static final String DAON_EXECUTOR_NAME = "DaonExecutor";

    @Override
    public String getName() {
        return DAON_EXECUTOR_NAME;
    }

    @Override
    public String getAMRValue() {
        return DAON_EXECUTOR_NAME;
    }

    /**
     * Declares the flows this executor can be used in.
     */
    @Override
    public Set<FlowTypes> getSupportedFlowTypes() {

        return EnumSet.allOf(FlowTypes.class);
    }

    /**
     * Describes how the flow composer should present this step.
     */
    @Override
    public FlowExecutorMetadata getExecutorMetadata() {

        return FlowExecutorMetadata.builder()
                .displayName(DaonConstants.AUTHENTICATOR_FRIENDLY_NAME + " Verification")
                .description("Verify user identity with Daon TrustX.")
                .icon("assets/images/icons/daon.svg")
                .behaviorFlags(Collections.singletonList(ExecutorBehaviorFlags.RECOVERY_FACTOR))
                .associatedAuthenticator(DaonConstants.AUTHENTICATOR_NAME)
                .connectionRequired(true)
                .build();
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext flowExecutionContext) {

        // Daon can return a standard OAuth2 error on the callback (e.g. the user cancelled/declined, or a
        // Daon-side failure) in place of a code. Detect it generically and fail with a user-facing message;
        // otherwise OpenIDConnectExecutor.isInitialRequest treats the missing code as an initial request and
        // re-redirects to Daon in a loop. Log the raw values so Daon-specific codes can be mapped later.
        Map<String, String> userInputs = flowExecutionContext.getUserInputData();
        if (userInputs != null
                && StringUtils.isNotBlank(userInputs.get(OIDCAuthenticatorConstants.OAUTH2_ERROR))) {
            String error = userInputs.get(OIDCAuthenticatorConstants.OAUTH2_ERROR);
            String errorDescription = userInputs.get(OAUTH2_ERROR_DESCRIPTION);
            ErrorMessage callbackError = DaonCallbackErrors.resolveError(error, errorDescription);
            if (LOG.isDebugEnabled()) {
                LOG.debug(callbackError.getCode() + " - Daon returned an error on the flow callback. error="
                        + error + ", error_description=" + errorDescription);
            }
            return userError(callbackError);
        }

        flowExecutionContext.setPortalUrl(
                buildPortalUrl(flowExecutionContext.getTenantDomain(), flowExecutionContext.getFlowType()));
        try {
            prepareRequest(flowExecutionContext);
        } catch (FlowEngineException e) {
            // The request cannot be built in a form that actually verifies the user (see prepareRequest),
            // so fail instead of sending Daon a request that would report success regardless.
            LOG.error(e.getErrorCode() + " - " + e.getDescription(), e);
            ExecutorResponse errorResponse = new ExecutorResponse();
            errorResponse.setResult(Constants.ExecutorStatus.STATUS_ERROR);
            errorResponse.setErrorCode(e.getErrorCode());
            errorResponse.setErrorMessage(e.getMessage());
            errorResponse.setErrorDescription(e.getDescription());
            return errorResponse;
        }
        // Password recovery re-verifies an already-Daon-enrolled user via login_hint. Without a Daon
        // association there is no login_hint to send, so fail cleanly instead of attempting enrolment.
        if (FLOW_TYPE_PASSWORD_RECOVERY.equals(flowExecutionContext.getFlowType())
                && StringUtils.isBlank(flowExecutionContext.getAuthenticatorProperties().get(DAON_LOGIN_HINT))) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_USER_NOT_ENROLLED,
                    flowExecutionContext.getFlowType()));
            return userError(ErrorMessage.ERROR_USER_NOT_ENROLLED);
        }
        return super.execute(flowExecutionContext);
    }

    /**
     * Ends the flow with a failure the end user is meant to see.
     *
     * <p>The flow engine copies the code, message and description straight off the {@link ExecutorResponse}
     * into the client error response, so this is the channel that carries the {@code DAON-} code to the
     * portal. The message and description are the error's {@code {{ }}} i18n tokens: the portal renders an
     * executor's wording only when it arrives wrapped that way, and otherwise keeps its own localized
     * flow-type wording — which is what the errors with no key (the administrator-facing ones) want.</p>
     *
     * <p>The diagnostic description is not sent; log it separately where the detail is needed.</p>
     *
     * <p>{@code setErrorMessage} is deprecated in favour of {@code addMessage}, but that is not an option
     * here: {@code TaskExecutionNode} carries an executor's messages only on {@code STATUS_RETRY}, and
     * discards them on {@code STATUS_USER_ERROR}. {@code STATUS_RETRY} in turn re-renders the current
     * node's page, which a Daon execution step does not have — the flow engine dereferences the missing
     * page mapping. Until that gap closes, the error object is the only channel out.</p>
     */
    private ExecutorResponse userError(ErrorMessage error) {

        ExecutorResponse response = new ExecutorResponse();
        response.setResult(Constants.ExecutorStatus.STATUS_USER_ERROR);
        response.setErrorCode(error.getCode());
        response.setErrorMessage(DaonExceptionMgt.userMessage(error));
        response.setErrorDescription(DaonExceptionMgt.userDescription(error));
        return response;
    }

    /**
     * Enriches the authenticator properties before the parent builds the authorize request:
     * the OIDC {@code claims} request (from the IDP claim mappings), the selected process definition
     * ({@code acr_values}), and — for password recovery — the {@code login_hint}. Client credentials,
     * endpoints, scope and callback are resolved natively by {@link OpenIDConnectExecutor}.
     *
     * <p>The {@code claims} parameter is built here, rather than in {@link #getAdditionalQueryParams}
     * whose signature cannot report a failure, so that a request which cannot be built to actually verify
     * the user fails the flow. Dropping the value-requests would leave Daon validating the presented
     * document against nothing while still returning success.</p>
     *
     * @throws FlowEngineException if the {@code claims} request cannot be built, or if an invited-user
     *                            flow has no document-verifiable attribute to validate the profile with.
     */
    private void prepareRequest(FlowExecutionContext flowExecutionContext) throws FlowEngineException {

        Map<String, String> props = flowExecutionContext.getAuthenticatorProperties();
        // A referencing login connection sets daon_idp_id and its OIDC credentials/endpoints live on the
        // referenced Daon Identity Verifier connection; resolve and inject them so the parent
        // OpenIDConnectExecutor builds the request against the Daon endpoints. A self-contained Identity
        // Verification connection already carries these on its own props, so injection is a no-op.
        Map<String, String> enriched =
                DaonReferencedIdpUtil.buildEffectiveProperties(props, flowExecutionContext.getTenantDomain());

        boolean recovery = FLOW_TYPE_PASSWORD_RECOVERY.equals(flowExecutionContext.getFlowType());
        Map<String, String> claimMappings = getIdpClaimMappings(flowExecutionContext);
        // Recovery re-verifies by face against a login_hint and requests no claims, so this applies to the
        // enrolment flows only.
        if (!recovery) {
            // Any mapped attribute the user already has (registration form input, invited user's
            // existing profile) is sent to Daon as a value-request so it verifies against that value
            // instead of returning it unverified.
            Map<String, String> prefilledValues = claimMappings.isEmpty()
                    ? Collections.emptyMap()
                    : resolvePrefilledClaimValues(flowExecutionContext, claimMappings);
            // Checked even when nothing is mapped: a connection with no claim mappings at all is the most
            // complete version of having nothing for Daon to validate the invited profile against.
            assertProfileCanBeValidated(flowExecutionContext, prefilledValues);
            if (!claimMappings.isEmpty()) {
                enriched.put(DAON_CLAIMS_REQUEST, buildClaimsRequest(claimMappings, prefilledValues));
            }
        }
        // The enrolment flows (registration, invited-user) send the enrol process definition; password
        // recovery sends the login one (re-verification). Both are read from the *effective* properties,
        // not the connection's own: the enrol PD is configured on the Daon Identity Verifier connection, so
        // for a referencing connection it only exists on `enriched` (buildEffectiveProperties layers it in
        // from the referenced IDP). Reading it from `props` would silently drop acr_values there and let
        // Daon run its default process definition. The login PD belongs to the login connection and is
        // deliberately not a referenced key, so for it the two maps hold the same value.
        String processDefinition = recovery ? enriched.get(DAON_LOGIN_PD) : enriched.get(DAON_ENROL_PD);
        if (StringUtils.isNotBlank(processDefinition)) {
            enriched.put(DAON_SELECTED_PD, processDefinition);
        }

        if (recovery) {
            String loginHint = resolvePreferredUsername(flowExecutionContext);
            if (StringUtils.isNotBlank(loginHint)) {
                enriched.put(DAON_LOGIN_HINT, loginHint);
            }
        }
        flowExecutionContext.setAuthenticatorProperties(enriched);
    }

    /**
     * Builds the OIDC {@code claims} request parameter for the enrolment flows.
     *
     * @throws FlowEngineException {@code DAON-65017} if it cannot be built — the flow must not continue
     *                             with the value-requests silently dropped.
     */
    private String buildClaimsRequest(Map<String, String> claimMappings, Map<String, String> prefilledValues)
            throws FlowEngineException {

        List<String> claimNames = new ArrayList<>(claimMappings.values());
        try {
            return DaonClaimsRequestBuilder.buildClaimsParam(claimNames, prefilledValues);
        } catch (DaonServerException e) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_BUILDING_CLAIMS_REQUEST), e);
            throw DaonExceptionMgt.toFlowServerException(e);
        }
    }

    /**
     * Guards the invited-user flow's core guarantee: that Daon validates the pre-populated profile against
     * the identity document, locking the account on a mismatch.
     *
     * <p>That guarantee rests entirely on the claim value-requests, because the connector deliberately does
     * no client-side re-validation of the returned claims (Daon reports a mismatch on the callback
     * instead). If none of the invited user's known attributes is document-verifiable — because the profile
     * is empty, because reading it failed, or because only attributes like email are mapped — then Daon has
     * nothing to compare and the flow would report success for any valid document. Fail instead.</p>
     *
     * <p>Self-registration is exempt: there Daon is the source of truth and provisions the profile from the
     * verified claims, so there is no pre-existing profile to validate against.</p>
     */
    private void assertProfileCanBeValidated(FlowExecutionContext flowExecutionContext,
                                             Map<String, String> prefilledValues) throws FlowEngineException {

        if (!FLOW_TYPE_INVITED_USER_REGISTRATION.equals(flowExecutionContext.getFlowType())) {
            return;
        }
        if (DaonClaimsRequestBuilder.hasDocumentVerifiableValue(prefilledValues)) {
            return;
        }
        LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_NO_VERIFIABLE_CLAIM_VALUES,
                flowExecutionContext.getFlowType()));
        throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_NO_VERIFIABLE_CLAIM_VALUES,
                flowExecutionContext.getFlowType());
    }

    @Override
    public Map<String, String> getAdditionalQueryParams(Map<String, String> authenticatorProperties) {

        Map<String, String> params = new HashMap<>();
        // Process definition (as acr_values) applies to every flow that reaches Daon.
        String processDefinition = authenticatorProperties.get(DAON_SELECTED_PD);
        if (StringUtils.isNotBlank(processDefinition)) {
            params.put(ACR_VALUES_PARAM, processDefinition);
        }
        String loginHint = authenticatorProperties.get(DAON_LOGIN_HINT);
        if (StringUtils.isNotBlank(loginHint)) {
            // Password recovery flow: face auth with login_hint, no verified_claims needed.
            params.put(LOGIN_HINT, loginHint);
            return params;
        }
        // Registration / invited user flow: request verified_claims from Daon. Built and validated in
        // prepareRequest, which has already failed the flow if it could not be produced.
        String claimsRequest = authenticatorProperties.get(DAON_CLAIMS_REQUEST);
        if (StringUtils.isNotBlank(claimsRequest)) {
            params.put(CLAIMS_PARAM, claimsRequest);
        }
        return params;
    }

    @Override
    protected Map<String, Object> resolveUserAttributes(FlowExecutionContext flowExecutionContext, String code)
            throws FlowEngineException {

        if (FLOW_TYPE_PASSWORD_RECOVERY.equals(flowExecutionContext.getFlowType())) {
            return resolvePasswordRecoveryAttributes(flowExecutionContext, code);
        }

        OAuthClientResponse oAuthResponse = requestAccessToken(flowExecutionContext, code);
        resolveAccessToken(oAuthResponse);

        String idToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);
        if (StringUtils.isBlank(idToken)) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_ID_TOKEN_NOT_FOUND,
                    flowExecutionContext.getFlowType());
        }

        JSONObject idTokenPayload;
        JSONObject daonClaims;
        try {
            idTokenPayload = DaonJwtUtil.decodeJwtPayload(idToken);
            // Fails the flow when the token carries no verification result: an enrolment step that
            // completes without one would mark the user verified on the strength of nothing.
            daonClaims = DaonJwtUtil.extractVerifiedClaims(idTokenPayload,
                    flowExecutionContext.getFlowType());
        } catch (DaonException e) {
            // The flow engine's generic handling reports the failure without this code, so log it here:
            // for an integrity failure on the verification result the code is what points at the cause.
            LOG.error(e.getErrorCode() + " - " + e.getMessage(), e);
            throw DaonExceptionMgt.toFlowServerException(e);
        }

        String subject = idTokenPayload.optString(DaonConstants.JWT_SUBJECT_CLAIM, null);
        if (StringUtils.isBlank(subject)) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_SUBJECT_CLAIM_NOT_FOUND,
                    flowExecutionContext.getFlowType());
        }

        Map<String, Object> userAttributes = new HashMap<>();

        Map<String, String> claimMappings = getIdpClaimMappings(flowExecutionContext);
        Map<String, String> reverseClaimMap = new HashMap<>();
        for (Map.Entry<String, String> entry : claimMappings.entrySet()) {
            reverseClaimMap.put(entry.getValue(), entry.getKey()); // Daon name -> WSO2 URI
        }

        Map<String, String> extractedClaims = new HashMap<>();
        for (Object keyObj : daonClaims.keySet()) {
            String key = (String) keyObj;
            String claimValue = DaonJwtUtil.resolveClaimValue(key, daonClaims.get(key));
            if (claimValue == null) {
                continue;
            }
            String claimUri = reverseClaimMap.getOrDefault(key,
                    DaonConstants.CLAIM_DIALECT_URI + "/" + key);
            extractedClaims.put(claimUri, claimValue);
        }

        String preferredUsername = idTokenPayload.optString(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM, null);

        // Verification of the user's details against the identity document is performed by Daon itself: the
        // invited user's (and self-registrant's) already-known claims are sent to Daon as OIDC claim
        // value-requests, and Daon returns a CLAIMS_VERIFICATION_MISMATCH error on the callback if they do
        // not match (surfaced as a user-facing error in execute()). A successful callback (a code) means
        // Daon accepted the details, so no client-side re-validation is done here.

        // Self-registration: Daon is the source of truth, so provision the new user's profile.
        if (FLOW_TYPE_REGISTRATION.equals(flowExecutionContext.getFlowType())) {
            userAttributes.putAll(buildProfileClaims(daonClaims, extractedClaims));
        }

        // Record the Daon verification as a federated association (local user <-> Daon subject),
        // persisted by DaonFederatedAssociationListener once the user exists. No custom user claims.
        // The association is keyed on the Daon IDP name — the self-contained Identity Verifier
        // connection's own name for enrolment — so it is shared with every login connection referencing
        // it (which resolve the same name via daon_idp_id).
        //
        // Every flow reaching here is an enrolment (password recovery returned above), and the association
        // is the only record of it. Fail rather than let the flow complete without one: the registration
        // would report success and the user would be told they are not enrolled at their first login,
        // with no way back to an enrolment.
        if (StringUtils.isBlank(preferredUsername)) {
            throw DaonExceptionMgt.handleFlowServerException(
                    ErrorMessage.ERROR_ENROLMENT_IDENTITY_NOT_RETURNED);
        }
        String daonIdpName = resolveDaonIdpName(flowExecutionContext);
        if (StringUtils.isBlank(daonIdpName)) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_PERSISTING_FED_ASSOCIATION,
                    "the Daon Verifier name could not be resolved for the " + flowExecutionContext.getFlowType()
                            + " flow");
        }
        flowExecutionContext.setProperty(DAON_FED_IDP_NAME, daonIdpName);
        flowExecutionContext.setProperty(DAON_FED_SUBJECT, preferredUsername);
        return userAttributes;
    }

    private Map<String, Object> resolvePasswordRecoveryAttributes(FlowExecutionContext flowExecutionContext,
                                                                   String code) throws FlowEngineException {

        OAuthClientResponse oAuthResponse = requestAccessToken(flowExecutionContext, code);
        resolveAccessToken(oAuthResponse);

        String idToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);
        if (StringUtils.isBlank(idToken)) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_ID_TOKEN_NOT_FOUND,
                    flowExecutionContext.getFlowType());
        }
        JSONObject idTokenPayload;
        try {
            idTokenPayload = DaonJwtUtil.decodeJwtPayload(idToken);
        } catch (DaonException e) {
            throw DaonExceptionMgt.toFlowServerException(e);
        }
        String returnedPreferredUsername =
                idTokenPayload.optString(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM, null);
        if (StringUtils.isBlank(returnedPreferredUsername)) {
            throw DaonExceptionMgt.handleFlowServerException(
                    ErrorMessage.ERROR_NO_SUBJECT_IDENTITY_IN_ID_TOKEN);
        }

        // Bind the verified identity back to the account being recovered. login_hint is only a hint per
        // OIDC — Daon verifies whoever actually presents themselves — so without this check anyone who
        // completes a Daon verification with their own enrolled account satisfies the identity-proofing
        // step for any other user's password reset. The hint is non-blank by the time we get here:
        // execute() fails the flow up front when the user has no Daon association.
        String expectedSubject = flowExecutionContext.getAuthenticatorProperties().get(DAON_LOGIN_HINT);
        if (!DaonJwtUtil.isExpectedSubject(expectedSubject, returnedPreferredUsername)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Daon returned an identity that does not match the account being recovered. "
                        + "Expected: " + expectedSubject + ", returned preferred_username: "
                        + returnedPreferredUsername);
            }
            // A client error, not a server fault: Daon worked correctly, it just verified someone other
            // than the account holder being recovered. The compared identifiers are in the debug line
            // above, so this one carries no personal identifier.
            LOG.error(ErrorMessage.ERROR_RECOVERY_IDENTITY_MISMATCH.getCode()
                    + " - The identity Daon verified does not match the Daon subject recorded for the "
                    + "account being recovered.");
            throw DaonExceptionMgt.handleFlowClientException(ErrorMessage.ERROR_RECOVERY_IDENTITY_MISMATCH);
        }
        return new HashMap<>();
    }

    /**
     * Builds the subset of Daon-verified claims to write to a self-registering user's profile.
     */
    private Map<String, Object> buildProfileClaims(JSONObject daonClaims, Map<String, String> extractedClaims) {

        Map<String, Object> profileClaims = new HashMap<>();
        for (Map.Entry<String, String> entry : extractedClaims.entrySet()) {
            if (!entry.getKey().startsWith(DaonConstants.CLAIM_DIALECT_URI)) {
                profileClaims.put(entry.getKey(), entry.getValue());
            }
        }
        populateNameClaims(daonClaims, profileClaims);
        return profileClaims;
    }

    /**
     * Ensures givenname/lastname are populated. Split {@code given_name}/{@code family_name} claims take
     * precedence; otherwise Daon's combined {@code family_name_and_given_name} is split on {@code ^}.
     */
    private void populateNameClaims(JSONObject daonClaims, Map<String, Object> profileClaims) {

        boolean hasGiven = profileClaims.containsKey(WSO2_GIVENNAME_CLAIM_URI);
        boolean hasLast = profileClaims.containsKey(WSO2_LASTNAME_CLAIM_URI);
        if (hasGiven && hasLast) {
            return;
        }
        String combined = DaonJwtUtil.resolveClaimValue(DaonConstants.CLAIM_FAMILY_NAME_AND_GIVEN_NAME,
                daonClaims.opt(DaonConstants.CLAIM_FAMILY_NAME_AND_GIVEN_NAME));
        if (StringUtils.isBlank(combined)
                || !combined.contains(DaonConstants.DAON_FIELD_SEPARATOR)) {
            return;
        }
        String[] parts = combined.split(
                java.util.regex.Pattern.quote(DaonConstants.DAON_FIELD_SEPARATOR), 2);
        String familyName = parts[0].trim();
        String givenName = parts.length > 1 ? parts[1].trim() : null;
        if (!hasGiven && StringUtils.isNotBlank(givenName)) {
            profileClaims.put(WSO2_GIVENNAME_CLAIM_URI, givenName);
        }
        if (!hasLast && StringUtils.isNotBlank(familyName)) {
            profileClaims.put(WSO2_LASTNAME_CLAIM_URI, familyName);
        }
    }

    /**
     * Resolves the invited (already-existing) user's values for the given claim URIs. The flow engine
     * does not guarantee the invited user's claims are loaded into the flow user, so values are taken
     * from the flow user first and any still-missing ones are read from the user store by user id.
     */
    private Map<String, String> resolveInvitedUserClaims(FlowExecutionContext context, Set<String> claimUris) {

        Map<String, String> resolved = new HashMap<>();
        FlowUser flowUser = context.getFlowUser();
        if (flowUser == null || claimUris.isEmpty()) {
            return resolved;
        }
        for (String uri : claimUris) {
            Object value = flowUser.getClaim(uri);
            if (value != null && StringUtils.isNotBlank(value.toString())) {
                resolved.put(uri, value.toString());
            }
        }
        String userId = flowUser.getUserId();
        if (StringUtils.isBlank(userId)) {
            return resolved;
        }
        List<String> missing = new ArrayList<>();
        for (String uri : claimUris) {
            if (!resolved.containsKey(uri)) {
                missing.add(uri);
            }
        }
        if (missing.isEmpty()) {
            return resolved;
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(context.getTenantDomain());
            org.wso2.carbon.user.api.UserStoreManager usm = DaonConnectorDataHolder.getRealmService()
                    .getTenantUserRealm(tenantId).getUserStoreManager();
            if (usm instanceof UniqueIDUserStoreManager) {
                Map<String, String> stored = ((UniqueIDUserStoreManager) usm)
                        .getUserClaimValuesWithID(userId, missing.toArray(new String[0]), null);
                if (stored != null) {
                    for (Map.Entry<String, String> entry : stored.entrySet()) {
                        if (StringUtils.isNotBlank(entry.getValue())) {
                            resolved.put(entry.getKey(), entry.getValue());
                        }
                    }
                }
            }
        } catch (UserStoreException e) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_READING_USER_CLAIMS), e);
        }
        return resolved;
    }

    /**
     * Resolves the Daon {@code preferred_username} for the flow user (used as {@code login_hint} in
     * password recovery) from the user's federated association with the Daon IDP.
     */
    private String resolvePreferredUsername(FlowExecutionContext context) {

        if (context.getFlowUser() == null) {
            return null;
        }
        String username = context.getFlowUser().getUsername();
        if (StringUtils.isBlank(username)) {
            return null;
        }
        // Look up the association against the Daon IDP the enrolment was recorded under: the referenced
        // Identity Verifier connection (via daon_idp_id) for a login connection, shared across every
        // login connection referencing the same one.
        String daonIdpName = resolveDaonIdpName(context);
        if (StringUtils.isBlank(daonIdpName)) {
            return null;
        }
        User user = DaonFederatedAssociationUtil.buildUser(username, context.getTenantDomain());
        return DaonFederatedAssociationUtil.getAssociatedDaonSubject(user, daonIdpName);
    }

    /**
     * Resolves the Daon IDP name the federated association is keyed on: the referenced Identity
     * Verification connection's name when {@code daon_idp_id} is set (login connection), otherwise this
     * connection's own name (self-contained Identity Verifier connection).
     */
    private String resolveDaonIdpName(FlowExecutionContext context) {

        String idpResourceId = context.getAuthenticatorProperties().get(DAON_IDP_ID);
        if (StringUtils.isNotBlank(idpResourceId)) {
            return DaonReferencedIdpUtil.resolveIdpName(idpResourceId, context.getTenantDomain());
        }
        return context.getExternalIdPConfig() != null
                ? context.getExternalIdPConfig().getIdPName() : null;
    }

    /**
     * Builds the dynamic flow-portal URL used as the OIDC {@code redirect_uri} the flow engine sends to
     * Daon; the browser returns here with the {@code code}/{@code state} and the portal resumes the flow.
     * The portal path is flow-specific: password recovery uses the recovery portal ({@code /accounts/recovery})
     * while registration and invited-user registration use the self-registration portal
     * ({@code /accounts/register}) — mirroring the IS authentication-portal dynamic portal routes.
     */
    private String buildPortalUrl(String tenantDomain, String flowType) {

        String portalPath = "/accounts/"
                + (FLOW_TYPE_PASSWORD_RECOVERY.equals(flowType) ? "recovery" : "register");
        try {
            if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                return IdentityUtil.getServerURL(portalPath, true, true);
            }
            if (OrganizationManagementUtil.isOrganization(tenantDomain)) {
                OrganizationManager orgManager = DaonConnectorDataHolder.getOrganizationManager();
                if (orgManager != null) {
                    String orgId = orgManager.resolveOrganizationId(tenantDomain);
                    return IdentityUtil.getServerURL("/o/" + orgId + portalPath, true, true);
                }
            }
            return IdentityUtil.getServerURL("/t/" + tenantDomain + portalPath, true, true);
        } catch (Exception e) {
            // Deliberately broad: organization resolution throws a checked OrganizationManagementException
            // while IdentityUtil.getServerURL can throw unchecked IdentityRuntimeException, and neither
            // should stop the flow when a usable default portal URL exists.
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_BUILDING_PORTAL_URL, tenantDomain), e);
            return IdentityUtil.getServerURL(portalPath, true, true);
        }
    }

    /**
     * Resolves the pre-known values of the mapped claims, keyed by Daon claim name, so they can be sent
     * to Daon as OIDC value-requests. For self-registration these come from what the user has entered so
     * far (the flow user's collected claims); for invited users they come from the existing profile
     * (flow user, falling back to the user store). Only mapped claims with a non-blank value are included.
     *
     * @param claimMappings WSO2 local claim URI -> Daon claim name.
     * @return Daon claim name -> value; empty when nothing is populated yet.
     */
    private Map<String, String> resolvePrefilledClaimValues(FlowExecutionContext context,
                                                             Map<String, String> claimMappings) {

        Map<String, String> localValues;
        if (FLOW_TYPE_INVITED_USER_REGISTRATION.equals(context.getFlowType())) {
            localValues = resolveInvitedUserClaims(context, claimMappings.keySet());
        } else {
            localValues = new HashMap<>();
            FlowUser flowUser = context.getFlowUser();
            Map<String, String> collectedClaims = flowUser != null ? flowUser.getClaims() : null;
            if (collectedClaims != null) {
                for (String localUri : claimMappings.keySet()) {
                    String value = collectedClaims.get(localUri);
                    if (StringUtils.isNotBlank(value)) {
                        localValues.put(localUri, value);
                    }
                }
            }
        }

        Map<String, String> valuesByDaonName = new HashMap<>();
        for (Map.Entry<String, String> mapping : claimMappings.entrySet()) {
            String value = localValues.get(mapping.getKey());
            if (StringUtils.isNotBlank(value)) {
                valuesByDaonName.put(mapping.getValue(), value.trim());
            }
        }
        return valuesByDaonName;
    }

    /**
     * Reads the IDP claim mappings (WSO2 local claim URI -> Daon remote claim name) from the connection's
     * claim configuration.
     */
    private Map<String, String> getIdpClaimMappings(FlowExecutionContext context) {

        Map<String, String> mappings = new HashMap<>();
        ExternalIdPConfig idpConfig = context.getExternalIdPConfig();
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
}
