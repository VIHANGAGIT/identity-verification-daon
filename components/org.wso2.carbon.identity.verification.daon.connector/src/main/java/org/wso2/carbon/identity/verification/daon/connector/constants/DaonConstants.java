/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.verification.daon.connector.constants;

import org.wso2.carbon.identity.verification.daon.connector.exception.DaonClientException;

/**
 * Constants used across the Daon TrustX connector — the API client, the login authenticator and the
 * flow executor.
 */
public class DaonConstants {

    private static final String IDV_ERROR_PREFIX = "DIDV-";

    private DaonConstants() {
    }

    public static final String DAON = "DAON";

    /*
     * The standard OIDC request/response parameters (client id, endpoints, scope, response type, grant
     * type, code, state, redirect URI) are not defined here: the authenticator and the executor extend
     * OpenIDConnectAuthenticator / OpenIDConnectExecutor, which own the protocol and read those keys via
     * OIDCAuthenticatorConstants. Only the Daon-specific parameters below are needed.
     */

    /** OIDC login_hint query parameter used to pre-identify the user on the Daon authorization endpoint. */
    public static final String LOGIN_HINT = "login_hint";

    /** OIDC request parameter carrying the selected Daon process definition. */
    public static final String ACR_VALUES_PARAM = "acr_values";

    /**
     * Standard OAuth2/OIDC error parameter returned on the callback when the user cancels/declines
     * verification or Daon fails (in place of {@code code}). The error code itself is read via
     * {@code OIDCAuthenticatorConstants.OAUTH2_ERROR}; there is no stock constant for the human-readable
     * {@code error_description}, so it is defined here.
     */
    public static final String OAUTH2_ERROR_DESCRIPTION = "error_description";

    /**
     * OIDC claims request parameter and verified_claims response keys.
     */
    public static final String CLAIMS_PARAM = "claims";
    /**
     * OIDC individual-claim-request member used to request that a claim be returned with (verified
     * against) a specific value, e.g. {@code "given_name": {"value": "JOHN"}}.
     */
    public static final String CLAIM_VALUE_MEMBER = "value";
    public static final String VERIFIED_CLAIMS = "verified_claims";
    public static final String VERIFICATION = "verification";
    public static final String TRUST_FRAMEWORK = "trust_framework";
    public static final String TRUST_FRAMEWORK_VALUE = "daon-identify-1";
    public static final String ID_TOKEN_CONTAINER = "id_token";

    /**
     * Daon verified claim names requested in the OIDC {@code claims} parameter.
     */
    public static final String CLAIM_GIVEN_NAME = "given_name";
    public static final String CLAIM_FAMILY_NAME = "family_name";
    public static final String CLAIM_FAMILY_NAME_AND_GIVEN_NAME = "family_name_and_given_name";
    public static final String CLAIM_DOCUMENT_TYPE = "document_type";
    public static final String CLAIM_DOCUMENT_CLASSIFICATION = "document_classification";
    public static final String CLAIM_DOCUMENT_DATE_OF_EXPIRY = "document_date_of_expiry";
    public static final String CLAIM_DOCUMENT_NUMBER = "document_number";
    public static final String CLAIM_DOCUMENT_PERSONAL_NUMBER = "document_personal_number";

    /**
     * Daon claim keys inside the "claims" JWT object, and the separator Daon uses inside its
     * multi-value fields.
     */
    public static final String CLAIM_ADDRESS = "address";
    public static final String CLAIM_ADDRESS_FORMATTED = "formatted";
    public static final String DAON_FIELD_SEPARATOR = "^";

    /**
     * Top-level JWT claim field names in the Daon ID token.
     */
    public static final String JWT_SUBJECT_CLAIM = "sub";
    public static final String JWT_VERIFIED_CLAIMS_OBJECT = "verifiedClaims";
    public static final String JWT_CLAIMS_OBJECT = "claims";

    /**
     * Daon preferred_username claim — the Daon-assigned identifier returned in the ID token.
     * Stored in the federated association after successful verification and used as login_hint during
     * face auth.
     */
    public static final String JWT_PREFERRED_USERNAME_CLAIM = "preferred_username";
    public static final String PREFERRED_USERNAME_CLAIM_URI = "http://wso2.org/daon/claims/preferred_username";

    /**
     * Metadata keys for storing Daon verification related details per claim.
     */
    public static final String DAON_STATE = "daon_state";
    public static final String DAON_FLOW_STATUS = "daon_flow_status";
    public static final String DAON_COMPLETED_AT = "daon_completed_at";
    public static final String DAON_VERIFICATION_STATUS = "daon_verification_status";
    public static final String DAON_AUTHORIZATION_URL = "daon_authorization_url";

    /**
     * Name of the federated authenticator handling the Daon login (re-verification) step, and the
     * friendly name shown for it.
     */
    public static final String AUTHENTICATOR_NAME = "DaonAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Daon TrustX";

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
     * Property key used to carry the pre-known values of the mapped claims (as a JSON object keyed by
     * Daon claim name) through the authenticator properties, so {@code getAdditionalQueryParams()} can
     * send them as OIDC value-requests in the {@code claims} parameter. Populated for the enrolment
     * flows from attributes the user already has before Daon is triggered.
     */
    public static final String DAON_CLAIM_VALUES = "daon_claim_values";

    /**
     * Property key used to carry the resolved {@code login_hint} (Daon {@code preferred_username})
     * into {@code getAdditionalQueryParams()} for the password recovery face-auth flow.
     */
    public static final String DAON_LOGIN_HINT = "daon_login_hint";

    /**
     * Flow-context property keys carrying the Daon federated association (IDP name + Daon subject /
     * preferred_username) from {@code DaonExecutor} to {@code DaonFederatedAssociationListener}, which
     * persists it once the flow completes and the user ID is available. The verification state lives in
     * the federated association store (IDP_USER_ID) — no custom user claims are required.
     */
    public static final String DAON_FED_IDP_NAME = "daon_fed_idp_name";
    public static final String DAON_FED_SUBJECT = "daon_fed_subject";

    /** Flow type strings returned by {@code FlowExecutionContext.getFlowType()}. */
    public static final String FLOW_TYPE_PASSWORD_RECOVERY = "PASSWORD_RECOVERY";
    public static final String FLOW_TYPE_REGISTRATION = "REGISTRATION";
    public static final String FLOW_TYPE_INVITED_USER_REGISTRATION = "INVITED_USER_REGISTRATION";

    /**
     * Stable error code surfaced to the authentication retry page when a user who is not enrolled with
     * Daon reaches the Daon login step. The framework drops an {@code AuthenticationFailedException}'s
     * error code before it reaches the portal, so the login authenticator redirects to the retry page
     * with this code as the {@code errorCode} query param, which the portal switches on to show a
     * dedicated "not enrolled" message.
     */
    public static final String USER_NOT_ENROLLED_ERROR_CODE = "DAON-60001";

    /**
     * i18n keys passed to the authentication retry page (as status / status message) when a not-enrolled
     * user reaches the Daon login step. The retry page resolves these from its resource bundle, so the
     * displayed text stays localizable and no raw sentence is hard-coded in the authenticator.
     */
    public static final String NOT_ENROLLED_RETRY_STATUS = "daon.user.not.enrolled.message";
    public static final String NOT_ENROLLED_RETRY_STATUS_MSG = "daon.user.not.enrolled.description";

    // Fallback claim dialect URI for Daon claims not mapped to a WSO2 local claim.
    public static final String CLAIM_DIALECT_URI = "http://wso2.org/daon/claims";

    public static final String USER_ID_CLAIM = "http://wso2.org/claims/userid";

    // WSO2 standard name claim URIs that may be matched against Daon's combined family_name_and_given_name.
    public static final String WSO2_LASTNAME_CLAIM_URI = "http://wso2.org/claims/lastname";
    public static final String WSO2_GIVENNAME_CLAIM_URI = "http://wso2.org/claims/givenname";

    /**
     * Error messages.
     */
    public enum ErrorMessage {

        ERROR_VERIFICATION_FLOW_STATUS_NOT_FOUND("10000",
                "Verification flow status is missing or undefined in the request"),
        ERROR_IDENTITY_VERIFICATION("10001",
                "Error while verifying the user identity through Daon TrustX."),
        ERROR_CLAIM_VALUE_NOT_EXIST("10002",
                "Required identity verification claim value does not exist."),
        ERROR_CREATING_RESPONSE("10003", "Error while creating the response."),
        ERROR_VERIFICATION_ALREADY_COMPLETED("10004",
                "Verification already completed. Cannot reinitiate a completed verification."),
        ERROR_INITIATING_DAON_VERIFICATION("10005",
                "Error occurred while initiating the verification in Daon for the user: %s."),
        ERROR_IDV_PROVIDER_INVALID_OR_DISABLED("10006",
                "IdVProvider is not available or not enabled"),
        ERROR_RESOLVING_IDV_PROVIDER("10007",
                "Error encountered while retrieving the identity verification provider."),
        ERROR_CREATING_HTTP_CLIENT("10008", "Server error encountered while creating http client"),
        ERROR_DAON_STATE_NOT_FOUND("10009", "No associated Daon state found. " +
                "Ensure that the verification process has been initiated before attempting to complete " +
                "or reinitiate it."),
        ERROR_IDV_PROVIDER_CONFIG_PROPERTIES_EMPTY("10010",
                "At least one IdVProvider configuration property is empty."),
        ERROR_INVALID_DAON_VERIFICATION_FLOW_STATUS("10011",
                "Invalid Daon verification flow status provided."),
        ERROR_RETRIEVING_CLAIMS_AGAINST_STATE("10012",
                "No claims found for the provided Daon state; the state may be incorrect or expired."),
        ERROR_UPDATING_IDV_CLAIM_VERIFICATION_STATUS("10013",
                "Error occurred while updating IDV claims verification status."),
        ERROR_BUILDING_DAON_AUTH_URI("10014",
                "Error occurred while building the Daon OIDC authorization URL."),
        ERROR_BUILDING_DAON_TOKEN_URI("10015",
                "Error occurred while building the Daon token endpoint URL."),
        ERROR_BUILDING_DAON_USERINFO_URI("10016",
                "Error occurred while building the Daon userinfo endpoint URL."),
        ERROR_EXCHANGING_CODE_FOR_TOKENS("10017",
                "Error occurred while exchanging the authorization code for tokens. Status: %s"),
        ERROR_GETTING_USERINFO("10018",
                "Error occurred while retrieving user info from Daon. Status: %s"),
        ERROR_INVALID_BASE_URL("10019", "Invalid Daon base URL provided."),
        ERROR_INVALID_CLIENT_CREDENTIALS("10020", "Invalid Daon client credentials provided."),
        ERROR_INVALID_OR_EXPIRED_CODE("10021", "Invalid or expired authorization code provided."),
        ERROR_STATE_MISMATCH("10022", "State parameter mismatch. Potential CSRF attack detected."),
        ERROR_CLAIM_MAPPING_NOT_FOUND("10023", "No Daon claim mapping found for the claim URI: %s."),
        ERROR_REINITIATING_DAON_VERIFICATION("10024",
                "An error occurred while reinitiating the verification."),
        ERROR_REINITIATION_NOT_ALLOWED("10025",
                "Reinitiation not allowed. Verification has already been completed."),
        ERROR_VERIFICATION_REQUIRED_CLAIMS_NOT_FOUND("10026",
                "Verification requested claims list cannot be empty."),
        ERROR_VERIFICATION_ALREADY_INITIATED("10027",
                "Verification has already been initiated for all requested claims.");

        private final String code;
        private final String message;

        ErrorMessage(String code, String message) {

            this.code = code;
            this.message = message;
        }

        public String getCode() {

            return IDV_ERROR_PREFIX + code;
        }

        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return code + ":" + message;
        }
    }

    /**
     * Enum representing the various statuses that a verification flow can transition through.
     */
    public enum VerificationFlowStatus {

        INITIATED("INITIATED"),
        COMPLETED("COMPLETED"),
        REINITIATED("REINITIATED");

        private final String status;

        VerificationFlowStatus(String status) {
            this.status = status;
        }

        public String getStatus() {
            return status;
        }

        public static VerificationFlowStatus fromString(String status) throws DaonClientException {

            for (VerificationFlowStatus flowStatus : VerificationFlowStatus.values()) {
                if (flowStatus.status.equalsIgnoreCase(status)) {
                    return flowStatus;
                }
            }
            throw new DaonClientException(ErrorMessage.ERROR_INVALID_DAON_VERIFICATION_FLOW_STATUS.getCode(),
                    ErrorMessage.ERROR_INVALID_DAON_VERIFICATION_FLOW_STATUS.getMessage());
        }

        @Override
        public String toString() {
            return this.status;
        }
    }

    /**
     * Enum representing the verification result for an identity claim returned by Daon.
     */
    public enum DaonVerificationStatus {

        VERIFIED("VERIFIED"),
        FAILED("FAILED"),
        MISMATCH("MISMATCH");

        private final String status;

        DaonVerificationStatus(String status) {
            this.status = status;
        }

        public String getStatus() {
            return status;
        }

        @Override
        public String toString() {
            return this.status;
        }
    }
}
