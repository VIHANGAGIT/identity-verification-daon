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

package org.wso2.carbon.identity.verification.daon.authenticator.constants;

/**
 * Constants for the Daon TrustX federated identity provider (IDP) — authenticator and flow executor.
 */
public class DaonAuthenticatorConstants {

    private DaonAuthenticatorConstants() {
    }

    public static final String AUTHENTICATOR_NAME = "DaonAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Daon TrustX";

    /** The /commonauth redirect URI used for the login authentication flow. */
    public static final String COMMON_AUTH_ENDPOINT = "/commonauth";

    /**
     * Query parameters on the OIDC callback request.
     */
    public static final String PARAM_CODE = "code";
    public static final String PARAM_STATE = "state";
    public static final String PARAM_SESSION_STATE = "session_state";

    /**
     * Standard OAuth2/OIDC error parameter returned on the callback when the user cancels/declines
     * verification or Daon fails (in place of {@code code}). The error code itself is read via
     * {@code OIDCAuthenticatorConstants.OAUTH2_ERROR}; there is no stock constant for the human-readable
     * {@code error_description}, so it is defined here.
     */
    public static final String OAUTH2_ERROR_DESCRIPTION = "error_description";

    /**
     * Authenticator configuration property key for the Daon <b>login</b> process definition (PD),
     * configured on the Daon TrustX Authenticator connection. It drives the login (re-verification)
     * flow and the password-recovery flow, and is sent to Daon as {@code acr_values} in the format
     * {@code <ProcessDefinitionName:Version>}. Enrolment flows (registration, invited-user) use the
     * enrol PD configured on the referenced Daon IDP instead ({@link #DAON_ENROL_PD}).
     */
    public static final String DAON_LOGIN_PD = "daon_login_pd";

    /**
     * Configuration property key for the Daon <b>enrol</b> process definition (PD), configured on the
     * referenced Daon TrustX IDP connection (not on the authenticator). It drives the enrolment flows
     * (registration and invited-user) and is sent to Daon as {@code acr_values}. Resolved at runtime
     * from the referenced IDP alongside its OIDC configuration.
     */
    public static final String DAON_ENROL_PD = "daon_enrol_pd";

    /**
     * Authenticator configuration property key holding the resource id (UUID) of the referenced Daon
     * OIDC IDP connection. The Daon TrustX Authenticator connection carries no OIDC credentials itself;
     * the client id/secret, authorize/token endpoints, scopes and enrol process definition are resolved
     * at runtime from this referenced IDP via {@link org.wso2.carbon.idp.mgt.IdpManager#getIdPByResourceId}.
     */
    public static final String DAON_IDP_ID = "daon_idp_id";

    /** OIDC request parameter carrying the selected Daon process definition. */
    public static final String ACR_VALUES_PARAM = "acr_values";

    /**
     * Internal authenticator-property key used to carry the resolved process definition into
     * {@code getAdditionalQueryParams()} for the executor (registration / recovery) flows.
     */
    public static final String DAON_SELECTED_PD = "daon_selected_pd";

    /**
     * Property key used to pass the comma-separated list of Daon claim names (from the IDP claim
     * mappings) through the authenticator properties so {@code getAdditionalQueryParams()} can build
     * the {@code claims} request parameter dynamically.
     */
    public static final String DAON_CLAIM_NAMES = "daon_claim_names";

    /**
     * Property key used to carry the resolved {@code login_hint} (Daon {@code preferred_username})
     * into {@code getAdditionalQueryParams()} for the password recovery face-auth flow.
     */
    public static final String DAON_LOGIN_HINT = "daon_login_hint";

    /** Flow type strings returned by {@code FlowExecutionContext.getFlowType()}. */
    public static final String FLOW_TYPE_PASSWORD_RECOVERY = "PASSWORD_RECOVERY";
    public static final String FLOW_TYPE_REGISTRATION = "REGISTRATION";
    public static final String FLOW_TYPE_INVITED_USER_REGISTRATION = "INVITED_USER_REGISTRATION";

    // Fallback claim dialect URI for Daon claims not mapped to a WSO2 local claim.
    public static final String CLAIM_DIALECT_URI = "http://wso2.org/daon/claims";

    // Top-level JWT claim field names.
    public static final String JWT_SUBJECT_CLAIM = "sub";
    public static final String JWT_VERIFIED_CLAIMS_OBJECT = "verifiedClaims";
    public static final String JWT_CLAIMS_OBJECT = "claims";

    // Daon claim keys inside the "claims" JWT object.
    public static final String CLAIM_ADDRESS = "address";
    public static final String CLAIM_ADDRESS_FORMATTED = "formatted";

    // Daon combined-name claim key and the separator Daon uses inside its multi-value fields.
    public static final String CLAIM_FAMILY_AND_GIVEN_NAME = "family_name_and_given_name";
    public static final String DAON_FIELD_SEPARATOR = "^";

    public static final String USER_ID_CLAIM = "http://wso2.org/claims/userid";

    // WSO2 standard name claim URIs that may be matched against Daon's combined family_name_and_given_name.
    public static final String WSO2_LASTNAME_CLAIM_URI = "http://wso2.org/claims/lastname";
    public static final String WSO2_GIVENNAME_CLAIM_URI = "http://wso2.org/claims/givenname";

    /**
     * Flow-context property keys carrying the Daon federated association (IDP name + Daon subject /
     * preferred_username) from {@code DaonExecutor} to {@code DaonFederatedAssociationListener}, which
     * persists it once the flow completes and the user ID is available. The verification state lives in
     * the federated association store (IDP_USER_ID) — no custom user claims are required.
     */
    public static final String DAON_FED_IDP_NAME = "daon_fed_idp_name";
    public static final String DAON_FED_SUBJECT = "daon_fed_subject";

    // IS identity claim used to lock a user account.
    public static final String ACCOUNT_LOCKED_CLAIM = "http://wso2.org/claims/identity/accountLocked";

    // Invited-user verification outcome + retry counting (flow-context property keys).
    public static final String DAON_VERIFICATION_OUTCOME = "daon_verification_outcome";
    public static final String DAON_VERIFICATION_ATTEMPTS = "daon_verification_attempts";
    public static final String OUTCOME_RETRY = "RETRY";
    public static final String OUTCOME_LOCKED = "LOCKED";

    // Number of failed Daon verification attempts (within an invited-user session) before the account
    // is locked. Failures below this threshold re-prompt the Daon step; at/above it the account is locked.
    public static final int MAX_VERIFICATION_ATTEMPTS = 3;
}
