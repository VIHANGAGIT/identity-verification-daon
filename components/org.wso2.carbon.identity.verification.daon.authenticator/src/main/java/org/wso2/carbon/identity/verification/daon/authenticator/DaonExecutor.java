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

package org.wso2.carbon.identity.verification.daon.authenticator;

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
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants;
import org.wso2.carbon.identity.verification.daon.authenticator.internal.DaonAuthenticatorDataHolder;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.web.DaonAPIClient;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.*;

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
            ExecutorResponse notEnrolled = new ExecutorResponse();
            notEnrolled.setResult(Constants.ExecutorStatus.STATUS_USER_ERROR);
            notEnrolled.setErrorMessage(
                    "The user is not enrolled with Daon TrustX, so identity cannot be verified for " +
                    "password recovery.");
            return notEnrolled;
        }
        ExecutorResponse response = super.execute(flowExecutionContext);
        String outcome = (String) flowExecutionContext.getProperty(DAON_VERIFICATION_OUTCOME);
        if (OUTCOME_LOCKED.equals(outcome)) {
            ExecutorResponse errorResponse = new ExecutorResponse();
            errorResponse.setResult(Constants.ExecutorStatus.STATUS_USER_ERROR);
            errorResponse.setErrorMessage(
                    "The details in your profile could not be verified by Daon after repeated attempts. " +
                    "Your account has been locked. Please contact support.");
            return errorResponse;
        }
        if (OUTCOME_RETRY.equals(outcome)) {
            // Re-prompt the Daon step (the code/state were cleared so it re-redirects).
            ExecutorResponse retryResponse = new ExecutorResponse();
            retryResponse.setResult(Constants.ExecutorStatus.STATUS_RETRY);
            retryResponse.setErrorMessage(
                    "Identity verification with Daon did not match your details. Please try again.");
            return retryResponse;
        }
        return response;
    }

    /**
     * Enriches the authenticator properties before the parent builds the authorize request:
     * the Daon claim names (from the IDP claim mappings), the selected process definition
     * ({@code acr_values}), and — for password recovery — the {@code login_hint}. Client credentials,
     * endpoints, scope and callback are resolved natively by {@link OpenIDConnectExecutor}.
     */
    private void prepareRequest(FlowExecutionContext flowExecutionContext) {

        Map<String, String> props = flowExecutionContext.getAuthenticatorProperties();
        Map<String, String> enriched = new HashMap<>(props);

        // A referencing login connection sets daon_idp_id and its OIDC credentials/endpoints live on the
        // referenced Daon Identity Verifier connection; resolve and inject them so the parent
        // OpenIDConnectExecutor builds the request against the Daon endpoints. A self-contained Identity
        // Verification connection already carries these on its own props, so injection is a no-op.
        Map<String, String> oidcConfig =
                DaonReferencedIdpUtil.resolveEffectiveOidcConfig(props, flowExecutionContext.getTenantDomain());
        copyIfPresent(oidcConfig, enriched, OIDCAuthenticatorConstants.CLIENT_ID);
        copyIfPresent(oidcConfig, enriched, OIDCAuthenticatorConstants.CLIENT_SECRET);
        copyIfPresent(oidcConfig, enriched, OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);
        copyIfPresent(oidcConfig, enriched, OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
        copyIfPresent(oidcConfig, enriched, IdentityApplicationConstants.Authenticator.OIDC.SCOPES);

        Map<String, String> claimMappings = getIdpClaimMappings(flowExecutionContext);
        if (!claimMappings.isEmpty()) {
            enriched.put(DAON_CLAIM_NAMES, String.join(",", claimMappings.values()));
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

    private static void copyIfPresent(Map<String, String> source, Map<String, String> target, String key) {

        String value = source.get(key);
        if (StringUtils.isNotBlank(value)) {
            target.put(key, value);
        }
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
            params.put("login_hint", loginHint);
            return params;
        }
        // Registration / invited user flow: request verified_claims from Daon.
        String claimNamesStr = authenticatorProperties.get(DAON_CLAIM_NAMES);
        if (StringUtils.isBlank(claimNamesStr)) {
            return params;
        }
        List<String> claimNames = Arrays.asList(claimNamesStr.split(","));
        params.put("claims", DaonAPIClient.buildClaimsParam(claimNames));
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
            throw handleFlowEngineServerException("ID token is empty or null.", null);
        }

        JSONObject idTokenPayload;
        try {
            idTokenPayload = DaonJwtUtil.decodeJwtPayload(idToken);
        } catch (IllegalArgumentException e) {
            throw handleFlowEngineServerException(e.getMessage(), e);
        }

        String subject = idTokenPayload.optString(DaonAuthenticatorConstants.JWT_SUBJECT_CLAIM, null);
        if (StringUtils.isBlank(subject)) {
            throw handleFlowEngineServerException("Subject (sub) claim not found in Daon ID token.", null);
        }

        Map<String, Object> userAttributes = new HashMap<>();

        if (!idTokenPayload.has(DaonAuthenticatorConstants.JWT_VERIFIED_CLAIMS_OBJECT)) {
            LOG.warn("No 'verifiedClaims' object in Daon ID token for subject: " + subject);
            return userAttributes;
        }
        JSONObject verifiedClaims = idTokenPayload.getJSONObject(DaonAuthenticatorConstants.JWT_VERIFIED_CLAIMS_OBJECT);
        if (!verifiedClaims.has(DaonAuthenticatorConstants.JWT_CLAIMS_OBJECT)) {
            LOG.warn("No 'claims' object inside 'verifiedClaims' in Daon ID token for subject: " + subject);
            return userAttributes;
        }
        JSONObject daonClaims = verifiedClaims.getJSONObject(DaonAuthenticatorConstants.JWT_CLAIMS_OBJECT);

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
                    DaonAuthenticatorConstants.CLAIM_DIALECT_URI + "/" + key);
            extractedClaims.put(claimUri, claimValue);
        }

        String preferredUsername = idTokenPayload.optString(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM, null);

        // Invited user flow: verify the admin-defined claims against the Daon-verified values. The
        // invited user already exists, so their claims are read from the flow user / user store.
        if (FLOW_TYPE_INVITED_USER_REGISTRATION.equals(flowExecutionContext.getFlowType())) {
            Map<String, String> userProfileClaims =
                    resolveInvitedUserClaims(flowExecutionContext, claimMappings.keySet());
            if (!validateProfileClaimsAgainstVerified(userProfileClaims, extractedClaims, claimMappings)) {
                handleVerificationFailure(flowExecutionContext);
                return userAttributes;
            }
        }

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
        String returnedSubject = idTokenPayload.optString(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM,
                idTokenPayload.optString(DaonAuthenticatorConstants.JWT_SUBJECT_CLAIM, null));
        if (StringUtils.isBlank(returnedSubject)) {
            throw handleFlowEngineServerException("No subject identity found in Daon ID token.", null);
        }
        return new HashMap<>();
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
            if (!entry.getKey().startsWith(DaonAuthenticatorConstants.CLAIM_DIALECT_URI)) {
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
        String combined = DaonJwtUtil.resolveClaimValue(DaonAuthenticatorConstants.CLAIM_FAMILY_AND_GIVEN_NAME,
                daonClaims.opt(DaonAuthenticatorConstants.CLAIM_FAMILY_AND_GIVEN_NAME));
        if (StringUtils.isBlank(combined)
                || !combined.contains(DaonAuthenticatorConstants.DAON_FIELD_SEPARATOR)) {
            return;
        }
        String[] parts = combined.split(
                java.util.regex.Pattern.quote(DaonAuthenticatorConstants.DAON_FIELD_SEPARATOR), 2);
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
            org.wso2.carbon.user.api.UserStoreManager usm = DaonAuthenticatorDataHolder.getRealmService()
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
     * Records a failed invited-user verification: increments the session attempt counter and either
     * re-prompts the Daon step (clearing the code/state so it re-redirects) or, once the attempts reach
     * {@link DaonAuthenticatorConstants#MAX_VERIFICATION_ATTEMPTS}, locks the account.
     */
    private void handleVerificationFailure(FlowExecutionContext context) {

        int attempts = parseAttempts(context.getProperty(DAON_VERIFICATION_ATTEMPTS)) + 1;
        context.setProperty(DAON_VERIFICATION_ATTEMPTS, String.valueOf(attempts));
        if (attempts >= MAX_VERIFICATION_ATTEMPTS) {
            lockUserAccount(context);
            context.setProperty(DAON_VERIFICATION_OUTCOME, OUTCOME_LOCKED);
        } else {
            if (context.getUserInputData() != null) {
                context.getUserInputData().remove("code");
                context.getUserInputData().remove("state");
            }
            context.setProperty(DAON_VERIFICATION_OUTCOME, OUTCOME_RETRY);
        }
    }

    private int parseAttempts(Object value) {

        if (value == null) {
            return 0;
        }
        try {
            return Integer.parseInt(value.toString());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /**
     * Validates each configured IDP claim URI that the invited user has a value for against the
     * corresponding Daon-verified value. For name claims where Daon returns a combined
     * {@code family_name_and_given_name} instead of separate {@code given_name}/{@code family_name},
     * the combined field is used as a fallback (contains check). Claims the user has no value for are
     * skipped (nothing to verify).
     *
     * @return {@code true} if all present claims match; {@code false} on any mismatch.
     */
    private boolean validateProfileClaimsAgainstVerified(
            Map<String, String> userProfileClaims,
            Map<String, String> extractedClaims,
            Map<String, String> claimMappings) {

        String combinedName = extractedClaims.get(
                DaonAuthenticatorConstants.CLAIM_DIALECT_URI + "/family_name_and_given_name");

        for (String wso2Uri : claimMappings.keySet()) {
            String profileValue = userProfileClaims.get(wso2Uri);
            if (StringUtils.isBlank(profileValue)) {
                continue;
            }
            profileValue = profileValue.trim();
            String verifiedValue = extractedClaims.get(wso2Uri);
            if (verifiedValue != null) {
                if (!verifiedValue.toLowerCase().contains(profileValue.toLowerCase())) {
                    LOG.warn("Claim mismatch for URI: " + wso2Uri);
                    return false;
                }
                continue;
            }
            boolean isNameClaim = WSO2_LASTNAME_CLAIM_URI.equals(wso2Uri)
                    || WSO2_GIVENNAME_CLAIM_URI.equals(wso2Uri);
            if (isNameClaim) {
                if (combinedName == null || !combinedName.toLowerCase().contains(profileValue.toLowerCase())) {
                    LOG.warn("Claim mismatch for URI: " + wso2Uri
                            + " (no direct Daon value; combined name check failed)");
                    return false;
                }
            } else {
                LOG.warn("No verified value available for claim URI: " + wso2Uri + "; skipping validation.");
            }
        }
        return true;
    }

    private void lockUserAccount(FlowExecutionContext context) {

        if (context.getFlowUser() == null) {
            LOG.warn("Cannot lock account: flow user is not available in context.");
            return;
        }
        String userId = context.getFlowUser().getUserId();
        if (StringUtils.isBlank(userId)) {
            LOG.warn("Cannot lock account: user ID is blank in flow context.");
            return;
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(context.getTenantDomain());
            org.wso2.carbon.user.api.UserStoreManager usm =
                    DaonAuthenticatorDataHolder.getRealmService()
                            .getTenantUserRealm(tenantId)
                            .getUserStoreManager();
            if (usm instanceof UniqueIDUserStoreManager) {
                Map<String, String> claimsToLock = new HashMap<>();
                claimsToLock.put(ACCOUNT_LOCKED_CLAIM, "true");
                ((UniqueIDUserStoreManager) usm).setUserClaimValuesWithID(userId, claimsToLock, null);
                LOG.warn("User account locked due to Daon verified-claim mismatch. User ID: " + userId);
            } else {
                LOG.warn("UniqueIDUserStoreManager not available; account not locked for user: " + userId);
            }
        } catch (UserStoreException e) {
            LOG.error("Failed to lock account for user: " + userId, e);
        }
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
                OrganizationManager orgManager = DaonAuthenticatorDataHolder.getOrganizationManager();
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
