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
 * Constants used in the Daon TrustX connector.
 */
public class DaonConstants {

    private static final String IDV_ERROR_PREFIX = "DIDV-";

    public static final String DAON = "DAON";

    /**
     * IdV provider configuration property keys.
     */
    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String AUTHORIZATION_ENDPOINT_URL = "authorization_endpoint";
    public static final String TOKEN_ENDPOINT_URL = "token_endpoint";
    public static final String SCOPE = "scope";
    public static final String CALLBACK_URL = "callback_url";

    /**
     * OIDC protocol constants.
     */
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String STATUS = "status";
    public static final String RESPONSE_TYPE = "response_type";
    public static final String RESPONSE_TYPE_CODE = "code";
    public static final String GRANT_TYPE = "grant_type";
    public static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String ID_TOKEN = "id_token";
    public static final String STATE = "state";

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
    public static final String VERIFIED_CLAIMS_ID_TOKEN = "verifiedClaims";
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
     * HTTP constants.
     */
    public static final String APPLICATION_JSON = "application/json";
    public static final String APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String BASIC_PREFIX = "Basic ";

    /**
     * Metadata keys for storing Daon verification related details per claim.
     */
    public static final String DAON_STATE = "daon_state";
    public static final String DAON_FLOW_STATUS = "daon_flow_status";
    public static final String DAON_COMPLETED_AT = "daon_completed_at";
    public static final String DAON_VERIFICATION_STATUS = "daon_verification_status";
    public static final String DAON_AUTHORIZATION_URL = "daon_authorization_url";

    /**
     * Daon preferred_username claim — the Daon-assigned identifier returned in the ID token.
     * Stored in the IDV claim store after successful IDV and used as login_hint during face auth.
     */
    public static final String JWT_PREFERRED_USERNAME_CLAIM = "preferred_username";
    public static final String PREFERRED_USERNAME_CLAIM_URI = "http://wso2.org/daon/claims/preferred_username";

    /** OIDC login_hint query parameter used to pre-identify the user on the Daon authorization endpoint. */
    public static final String LOGIN_HINT = "login_hint";

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
