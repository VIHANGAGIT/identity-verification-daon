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

package org.wso2.carbon.identity.verification.daon.connector.constants;

/**
 * Error catalogue for the Daon TrustX connector.
 *
 * <p>Every failure the connector can report has an entry here, so a code seen in a log line or in a flow
 * API error response maps to exactly one site in the code. Codes follow the WSO2 Identity Server
 * convention used across the connector pack: {@code 60xxx} for client errors (something the user or the
 * connection configuration can fix) and {@code 65xxx} for server errors. The {@code DAON-} prefix is
 * applied by {@link ErrorMessage#getCode()} rather than stored, so the enum literals stay bare digits.</p>
 *
 * @see org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt
 */
public class DaonErrorConstants {

    /** Prefix applied to every Daon error code, e.g. {@code DAON-65002}. */
    public static final String DAON_ERROR_PREFIX = "DAON-";

    private DaonErrorConstants() {
    }

    /**
     * Daon connector errors.
     *
     * <p>{@code message} is the short, user-safe title — for client errors this is the text the end user
     * sees. {@code description} is the diagnostic detail and may carry {@code %s} placeholders, formatted
     * with the caller's arguments by
     * {@link org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt}.</p>
     */
    public enum ErrorMessage {

        // Client errors - DAON-60xxx.

        /**
         * The user has no Daon federated association, so there is nothing to re-verify against.
         *
         * <p>The resulting {@code DAON-60001} is a published contract: the recovery portal and the login
         * retry page both switch on this literal. Do not renumber it.</p>
         */
        ERROR_USER_NOT_ENROLLED("60001",
                "Your account is not enrolled with Daon TrustX for identity verification. "
                        + "Please contact your administrator.",
                "No Daon federated association exists for the user in the %s flow."),

        ERROR_VERIFICATION_CANCELLED("60002",
                "Identity verification was cancelled or not completed. Please try again.",
                "Daon returned the access_denied error on the callback; the user cancelled or "
                        + "declined the verification."),

        ERROR_CLAIMS_VERIFICATION_MISMATCH("60003",
                "The details you entered do not match your identity document. "
                        + "Please check your information and try again.",
                "Daon reported CLAIMS_VERIFICATION_MISMATCH: the claim values sent as OIDC "
                        + "value-requests did not match the identity document."),

        ERROR_IDENTITY_VERIFICATION_FAILED("60004",
                "Your identity could not be verified. Please try again or contact support.",
                "Daon returned the FailedToVerifyUser error on the callback."),

        ERROR_VERIFICATION_NOT_COMPLETED("60005",
                "Identity verification could not be completed. Please try again or contact support.",
                "Daon returned an unrecognised error on the callback. error: %s, error_description: %s"),

        ERROR_RECOVERY_IDENTITY_MISMATCH("60006",
                "Identity verification failed: the verified identity does not match the user being "
                        + "recovered.",
                "The identity Daon verified does not match the Daon subject recorded for the account "
                        + "being recovered. Expected: %s"),

        ERROR_INVALID_VERIFICATION_FLOW_STATUS("60007",
                "Invalid Daon verification flow status provided.",
                "The verification flow status '%s' is not a recognised Daon flow status."),

        // Server errors - DAON-65xxx.

        ERROR_OIDC_CONFIG_NOT_RESOLVED("65001",
                "Could not resolve the Daon OIDC configuration. For a login connection, check the Daon "
                        + "Verifier ID it references; for a Daon Identity Verifier connection, check its own "
                        + "client id and endpoint configuration.",
                "The resolved authenticator properties are missing the client id or the %s endpoint."),

        ERROR_ID_TOKEN_NOT_FOUND("65002",
                "ID token not found in the Daon token response.",
                "Daon did not return an id_token in the token response for the %s flow."),

        ERROR_INVALID_ID_TOKEN("65003",
                "The Daon ID token is malformed.",
                "Invalid JWT: expected at least 2 segments, got %s."),

        ERROR_DECODING_ID_TOKEN("65004",
                "Could not decode the Daon ID token.",
                "Failed to Base64URL-decode or parse the payload segment of the Daon ID token."),

        ERROR_SUBJECT_CLAIM_NOT_FOUND("65005",
                "Subject claim not found in the Daon ID token.",
                "The 'sub' claim is missing from the Daon ID token in the %s flow."),

        ERROR_NO_SUBJECT_IDENTITY_IN_ID_TOKEN("65006",
                "No subject identity found in the Daon ID token.",
                "Neither 'preferred_username' nor 'sub' is present in the Daon ID token returned for "
                        + "password recovery."),

        ERROR_IDP_MANAGER_UNAVAILABLE("65007",
                "The identity provider management service is unavailable.",
                "IdpManager is not available; cannot resolve the referenced Daon IDP: %s"),

        ERROR_RESOLVING_REFERENCED_IDP("65008",
                "Could not resolve the referenced Daon identity provider.",
                "Error resolving the referenced Daon IDP for resource id: %s"),

        ERROR_REFERENCED_IDP_NOT_FOUND("65009",
                "The referenced Daon identity provider was not found.",
                "No identity provider exists for the referenced Daon resource id: %s"),

        ERROR_REFERENCED_IDP_NO_AUTHENTICATOR_CONFIG("65010",
                "The referenced Daon identity provider has no authenticator configuration.",
                "The referenced Daon IDP has no federated authenticator configuration: %s"),

        ERROR_FED_ASSOCIATION_MANAGER_UNAVAILABLE("65011",
                "The federated association management service is unavailable.",
                "FederatedAssociationManager is not available; %s"),

        ERROR_RESOLVING_FED_ASSOCIATION("65012",
                "Could not resolve the Daon federated association.",
                "Error resolving the Daon federated association for IDP: %s; treating the user as "
                        + "not verified."),

        ERROR_CREATING_FED_ASSOCIATION("65013",
                "Could not create the Daon federated association.",
                "Error creating the Daon federated association for IDP: %s (the association may "
                        + "already exist)."),

        ERROR_SKIPPING_FED_ASSOCIATION("65014",
                "The Daon federated association was not persisted.",
                "Skipped persisting the Daon federated association because %s; the user will be "
                        + "treated as not enrolled at the next login."),

        ERROR_READING_USER_CLAIMS("65015",
                "Could not read the user's stored claims.",
                "Error reading the invited user's stored claims for Daon verification; the "
                        + "corresponding claim value-requests will not be sent."),

        ERROR_PARSING_CLAIM_VALUES("65016",
                "Could not parse the pre-known Daon claim values.",
                "The %s property is not valid JSON; sending claim requests without values."),

        ERROR_BUILDING_CLAIMS_REQUEST("65017",
                "Could not build the Daon claims request.",
                "Error building the OIDC claims request parameter for the Daon authorization request."),

        ERROR_BUILDING_PORTAL_URL("65018",
                "Could not build the flow portal URL.",
                "Error building the portal URL for tenant: %s; falling back to the default portal URL."),

        ERROR_REDIRECTING_TO_RETRY_PAGE("65019",
                "Could not redirect to the login retry page.",
                "Error redirecting the not-enrolled user to the Daon login retry page."),

        ERROR_ACTIVATING_BUNDLE("65020",
                "Could not activate the Daon connector bundle.",
                "Error registering the Daon connector OSGi services; the bundle is active but one or "
                        + "more services may be unregistered.");

        private final String code;
        private final String message;
        private final String description;

        ErrorMessage(String code, String message, String description) {

            this.code = code;
            this.message = message;
            this.description = description;
        }

        /**
         * @return the prefixed error code, e.g. {@code DAON-65002}.
         */
        public String getCode() {

            return DAON_ERROR_PREFIX + code;
        }

        /**
         * @return the short title; for client errors this is the user-facing text.
         */
        public String getMessage() {

            return message;
        }

        /**
         * @return the diagnostic detail, possibly carrying {@code %s} placeholders.
         */
        public String getDescription() {

            return description;
        }

        @Override
        public String toString() {

            return getCode() + " - " + message;
        }
    }
}
