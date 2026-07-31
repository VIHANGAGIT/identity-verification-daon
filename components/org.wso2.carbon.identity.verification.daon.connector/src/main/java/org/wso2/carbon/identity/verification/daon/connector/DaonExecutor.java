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
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.internal.DaonConnectorDataHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ACR_VALUES_PARAM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIMS_PARAM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_CLAIM_NAMES;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_CLAIM_VALUES;
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
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.USER_NOT_ENROLLED_ERROR_CODE;
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
            if (LOG.isDebugEnabled()) {
                LOG.debug("Daon returned an error on the flow callback. error=" + error
                        + ", error_description=" + errorDescription);
            }
            ExecutorResponse errorResponse = new ExecutorResponse();
            errorResponse.setResult(Constants.ExecutorStatus.STATUS_USER_ERROR);
            errorResponse.setErrorMessage(DaonCallbackErrors.resolveUserFacingMessage(error, errorDescription));
            return errorResponse;
        }

        flowExecutionContext.setPortalUrl(
                buildPortalUrl(flowExecutionContext.getTenantDomain(), flowExecutionContext.getFlowType()));
        prepareRequest(flowExecutionContext);
        // Password recovery re-verifies an already-Daon-enrolled user via login_hint. Without a Daon
        // association there is no login_hint to send, so fail cleanly instead of attempting enrolment.
        if (FLOW_TYPE_PASSWORD_RECOVERY.equals(flowExecutionContext.getFlowType())
                && StringUtils.isBlank(flowExecutionContext.getAuthenticatorProperties().get(DAON_LOGIN_HINT))) {
            String notEnrolledMessage = "Your account is not enrolled with Daon TrustX for identity verification. "
                    + "Please contact your administrator.";
            ExecutorResponse notEnrolled = new ExecutorResponse();
            notEnrolled.setResult(Constants.ExecutorStatus.STATUS_USER_ERROR);
            // Set a stable, machine-readable error code so the recovery portal can switch on it (via the
            // flow API's error.code) instead of parsing the message. The flow engine propagates the
            // executor's error code/description straight through to the client error response.
            notEnrolled.setErrorCode(USER_NOT_ENROLLED_ERROR_CODE);
            notEnrolled.setErrorMessage(notEnrolledMessage);
            notEnrolled.setErrorDescription(notEnrolledMessage);
            return notEnrolled;
        }
        return super.execute(flowExecutionContext);
    }

    /**
     * Enriches the authenticator properties before the parent builds the authorize request:
     * the Daon claim names (from the IDP claim mappings), the selected process definition
     * ({@code acr_values}), and — for password recovery — the {@code login_hint}. Client credentials,
     * endpoints, scope and callback are resolved natively by {@link OpenIDConnectExecutor}.
     */
    private void prepareRequest(FlowExecutionContext flowExecutionContext) {

        Map<String, String> props = flowExecutionContext.getAuthenticatorProperties();
        // A referencing login connection sets daon_idp_id and its OIDC credentials/endpoints live on the
        // referenced Daon Identity Verifier connection; resolve and inject them so the parent
        // OpenIDConnectExecutor builds the request against the Daon endpoints. A self-contained Identity
        // Verification connection already carries these on its own props, so injection is a no-op.
        Map<String, String> enriched =
                DaonReferencedIdpUtil.buildEffectiveProperties(props, flowExecutionContext.getTenantDomain());

        Map<String, String> claimMappings = getIdpClaimMappings(flowExecutionContext);
        if (!claimMappings.isEmpty()) {
            enriched.put(DAON_CLAIM_NAMES, String.join(",", claimMappings.values()));
            // Any mapped attribute the user already has (registration form input, invited user's
            // existing profile) is sent to Daon as a value-request so it verifies against that value
            // instead of returning it unverified. Recovery does not request claims, so skip it there.
            if (!FLOW_TYPE_PASSWORD_RECOVERY.equals(flowExecutionContext.getFlowType())) {
                Map<String, String> prefilledValues =
                        resolvePrefilledClaimValues(flowExecutionContext, claimMappings);
                if (!prefilledValues.isEmpty()) {
                    enriched.put(DAON_CLAIM_VALUES, new JSONObject(prefilledValues).toString());
                }
            }
        }

        boolean recovery = FLOW_TYPE_PASSWORD_RECOVERY.equals(flowExecutionContext.getFlowType());
        // The enrolment flows (registration, invited-user) run on a self-contained Identity Verifier
        // connection and send its enrol process definition; password recovery runs on a login connection
        // and sends its login process definition (re-verification). Both are read from the connection's
        // own props and sent to Daon as acr_values.
        String processDefinition = recovery ? props.get(DAON_LOGIN_PD) : props.get(DAON_ENROL_PD);
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
        // Registration / invited user flow: request verified_claims from Daon.
        String claimNamesStr = authenticatorProperties.get(DAON_CLAIM_NAMES);
        if (StringUtils.isBlank(claimNamesStr)) {
            return params;
        }
        List<String> claimNames = Arrays.asList(claimNamesStr.split(","));
        Map<String, String> claimValues = parseClaimValues(authenticatorProperties.get(DAON_CLAIM_VALUES));
        params.put(CLAIMS_PARAM, DaonClaimsRequestBuilder.buildClaimsParam(claimNames, claimValues));
        return params;
    }

    /**
     * Parses the {@code daon_claim_values} property (a JSON object keyed by Daon claim name) back into a
     * map for {@link DaonClaimsRequestBuilder#buildClaimsParam(List, Map)}. Returns an empty map when the property
     * is absent or unparseable.
     */
    private Map<String, String> parseClaimValues(String serialized) {

        Map<String, String> values = new HashMap<>();
        if (StringUtils.isBlank(serialized)) {
            return values;
        }
        try {
            JSONObject json = new JSONObject(serialized);
            for (String key : json.keySet()) {
                values.put(key, json.getString(key));
            }
        } catch (org.json.JSONException e) {
            LOG.warn("Could not parse pre-known Daon claim values; sending claim requests without values.", e);
        }
        return values;
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
            throw handleFlowEngineServerException("ID token is empty or null.", null);
        }

        JSONObject idTokenPayload;
        try {
            idTokenPayload = DaonJwtUtil.decodeJwtPayload(idToken);
        } catch (IllegalArgumentException e) {
            throw handleFlowEngineServerException(e.getMessage(), e);
        }

        String subject = idTokenPayload.optString(DaonConstants.JWT_SUBJECT_CLAIM, null);
        if (StringUtils.isBlank(subject)) {
            throw handleFlowEngineServerException("Subject (sub) claim not found in Daon ID token.", null);
        }

        Map<String, Object> userAttributes = new HashMap<>();

        if (!idTokenPayload.has(DaonConstants.JWT_VERIFIED_CLAIMS_OBJECT)) {
            LOG.warn("No 'verifiedClaims' object in Daon ID token for subject: " + subject);
            return userAttributes;
        }
        JSONObject verifiedClaims = idTokenPayload.getJSONObject(DaonConstants.JWT_VERIFIED_CLAIMS_OBJECT);
        if (!verifiedClaims.has(DaonConstants.JWT_CLAIMS_OBJECT)) {
            LOG.warn("No 'claims' object inside 'verifiedClaims' in Daon ID token for subject: " + subject);
            return userAttributes;
        }
        JSONObject daonClaims = verifiedClaims.getJSONObject(DaonConstants.JWT_CLAIMS_OBJECT);

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
        String daonIdpName = resolveDaonIdpName(flowExecutionContext);
        if (StringUtils.isNotBlank(preferredUsername) && StringUtils.isNotBlank(daonIdpName)) {
            flowExecutionContext.setProperty(DAON_FED_IDP_NAME, daonIdpName);
            flowExecutionContext.setProperty(DAON_FED_SUBJECT, preferredUsername);
        }
        return userAttributes;
    }

    private Map<String, Object> resolvePasswordRecoveryAttributes(FlowExecutionContext flowExecutionContext,
                                                                   String code) throws FlowEngineException {

        OAuthClientResponse oAuthResponse = requestAccessToken(flowExecutionContext, code);
        resolveAccessToken(oAuthResponse);

        String idToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);
        if (StringUtils.isBlank(idToken)) {
            throw handleFlowEngineServerException("ID token is empty or null.", null);
        }
        JSONObject idTokenPayload;
        try {
            idTokenPayload = DaonJwtUtil.decodeJwtPayload(idToken);
        } catch (IllegalArgumentException e) {
            throw handleFlowEngineServerException(e.getMessage(), e);
        }
        String returnedPreferredUsername =
                idTokenPayload.optString(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM, null);
        String returnedSubject = idTokenPayload.optString(DaonConstants.JWT_SUBJECT_CLAIM, null);
        if (StringUtils.isBlank(returnedPreferredUsername) && StringUtils.isBlank(returnedSubject)) {
            throw handleFlowEngineServerException("No subject identity found in Daon ID token.", null);
        }

        // Bind the verified identity back to the account being recovered. login_hint is only a hint per
        // OIDC — Daon verifies whoever actually presents themselves — so without this check anyone who
        // completes a Daon verification with their own enrolled account satisfies the identity-proofing
        // step for any other user's password reset. The hint is non-blank by the time we get here:
        // execute() fails the flow up front when the user has no Daon association.
        String expectedSubject = flowExecutionContext.getAuthenticatorProperties().get(DAON_LOGIN_HINT);
        if (!isExpectedIdentity(expectedSubject, returnedPreferredUsername, returnedSubject)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Daon returned an identity that does not match the account being recovered. "
                        + "Expected: " + expectedSubject + ", returned preferred_username: "
                        + returnedPreferredUsername + ", returned sub: " + returnedSubject);
            }
            throw handleFlowEngineServerException(
                    "Identity verification failed: the verified identity does not match the user being "
                            + "recovered.", null);
        }
        return new HashMap<>();
    }

    /**
     * Checks the identity Daon returned against the Daon subject recorded in the user's federated
     * association (the value sent as {@code login_hint}).
     *
     * <p>Both the ID token's {@code preferred_username} and its {@code sub} are accepted, since either
     * may carry the enrolled identifier depending on the Daon tenant's configuration. Fails closed: a
     * blank expected subject never matches.</p>
     */
    private boolean isExpectedIdentity(String expectedSubject, String returnedPreferredUsername,
                                       String returnedSubject) {

        if (StringUtils.isBlank(expectedSubject)) {
            return false;
        }
        String expected = expectedSubject.trim();
        return expected.equalsIgnoreCase(StringUtils.trimToEmpty(returnedPreferredUsername))
                || expected.equalsIgnoreCase(StringUtils.trimToEmpty(returnedSubject));
    }

    /**
     * Builds the subset of Daon-verified claims to write to a self-registering user's profile.
     *
     * <p>Includes every verified claim that the IDP maps to a real WSO2 local claim URI. Claims that
     * fell back to a {@code http://wso2.org/daon/claims/*} dialect URI are excluded (they are not
     * necessarily registered local claims). Name claims are handled via {@link #populateNameClaims}.</p>
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
     *
     * <p><b>Assumption:</b> the combined field is ordered {@code <given names>^<family name>}. Confirm
     * against your Daon tenant; swap the two assignments below if it emits the opposite order.</p>
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
        String givenName = parts[0].trim();
        String familyName = parts.length > 1 ? parts[1].trim() : null;
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
            LOG.warn("Could not read the invited user's stored claims for Daon verification.", e);
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
            LOG.warn("Could not build portal URL for tenant: " + tenantDomain + "; falling back to default.", e);
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
