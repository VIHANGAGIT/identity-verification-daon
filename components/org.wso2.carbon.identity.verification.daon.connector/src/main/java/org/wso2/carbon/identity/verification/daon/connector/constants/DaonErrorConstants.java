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
     * <p>{@code message} is the short, user-safe title. {@code description} is the diagnostic detail and
     * may carry {@code %s} placeholders, formatted with the caller's arguments by
     * {@link org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt}.</p>
     *
     * <p>{@code i18nKey} names the flow portal resource bundle entry that renders the failure to the end
     * user, and is what makes an error user-facing at all: the portal shows an executor's message and
     * description only when they arrive wrapped as {@code {{key}}} tokens (see
     * {@link #getUserMessageToken()}), and falls back to its own localized flow-type wording otherwise.
     */
    public enum ErrorMessage {

        // Client errors - DAON-60xxx.

        /**
         * The user has no Daon federated association, so there is nothing to re-verify against.
         *
         * <p>The resulting {@code DAON-60001} is what an adaptive script's {@code onFail} handler keys off
         * to route a not-enrolled user into enrolment (see {@code docs/adaptive-scripts}). No portal reads
         * it: what the end user is shown comes from {@code i18nKey} below. Do not renumber it.</p>
         */
        ERROR_USER_NOT_ENROLLED("60001",
                "Your account is not enrolled with Daon TrustX for identity verification. "
                        + "Please contact your administrator.",
                "No Daon federated association exists for the user in the %s flow.",
                "daon.identity.verification.not.enrolled"),

        ERROR_VERIFICATION_CANCELLED("60002",
                "Identity verification was cancelled or not completed. Please try again.",
                "Daon returned the access_denied error on the callback; the user cancelled or "
                        + "declined the verification.",
                "daon.identity.verification.cancelled"),

        ERROR_CLAIMS_VERIFICATION_MISMATCH("60003",
                "The details you entered do not match your identity document. "
                        + "Please check your information and try again.",
                "Daon reported CLAIMS_VERIFICATION_MISMATCH: the claim values sent as OIDC "
                        + "value-requests did not match the identity document.",
                "daon.identity.verification.details.mismatch"),

        ERROR_IDENTITY_VERIFICATION_FAILED("60004",
                "Your identity could not be verified. Please try again or contact support.",
                "Daon returned the FailedToVerifyUser error on the callback.",
                "daon.identity.verification.failed"),

        ERROR_VERIFICATION_NOT_COMPLETED("60005",
                "Identity verification could not be completed. Please try again or contact support.",
                "Daon returned an unrecognised error on the callback. error: %s, error_description: %s",
                "daon.identity.verification.failed"),

        ERROR_RECOVERY_IDENTITY_MISMATCH("60006",
                "Identity verification failed: the verified identity does not match the user being "
                        + "recovered.",
                "The identity Daon verified does not match the Daon subject recorded for the account "
                        + "being recovered. Expected: %s",
                "daon.identity.verification.identity.mismatch"),

        ERROR_INVALID_VERIFICATION_FLOW_STATUS("60007",
                "Invalid Daon verification flow status provided.",
                "The verification flow status '%s' is not a recognised Daon flow status."),

        /**
         * The login step's counterpart to {@link #ERROR_RECOVERY_IDENTITY_MISMATCH}: Daon verified an
         * identity other than the one enrolled for the account being logged in to (or the enrolled
         * identity could not be resolved at the callback, in which case the binding cannot be proven).
         */
        ERROR_LOGIN_IDENTITY_MISMATCH("60008",
                "Identity verification failed: the verified identity does not match the account you are "
                        + "signing in to.",
                "The identity Daon verified does not match the Daon subject recorded for the "
                        + "authenticating user. The compared identifiers are logged at debug level, so "
                        + "this line carries no personal identifier."),

        /**
         * An enrolment was requested for a user who already has a Daon enrolment.
         *
         * <p>The check this reports is the one that keeps enrolment at login from becoming an account
         * takeover. Re-verification and enrolment are mutually exclusive by account state: a user with an
         * enrolment must satisfy it, and can never be routed around it into enrolling a second identity.
         * Someone holding the account's first-factor credentials but not its enrolled identity would
         * otherwise only have to fail the face verification to bind their own.</p>
         *
         * <p>Enforced in the authenticator, so no adaptive script can weaken it — a script asking to enrol
         * an already-enrolled user fails the step here.</p>
         */
        ERROR_ALREADY_ENROLLED("60009",
                "Your account is already enrolled for identity verification. Please complete the "
                        + "verification, or contact your administrator if you cannot.",
                "An enrolment was requested for a user who already has a Daon federated association on "
                        + "IDP: %s. Refusing to enrol a second identity for the account."),

        /**
         * An enrolment verified an identity that is already enrolled for a different local account.
         *
         * <p>Fails rather than logging the user in unenrolled: one Daon identity backing two accounts would
         * let the same person satisfy identity proofing for either of them.</p>
         */
        ERROR_DAON_IDENTITY_ALREADY_ENROLLED("60010",
                "The verified identity is already enrolled for another account. "
                        + "Please contact your administrator.",
                "The Daon subject returned by the enrolment is already associated with a different local "
                        + "user on IDP: %s"),

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
                "The 'preferred_username' claim is not present in the Daon ID token returned for "
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

        /**
         * The Daon verification could not be recorded against the user.
         *
         * <p>Raised, not just logged: an enrolment that is not recorded leaves the account looking
         * not-enrolled at the next login, so both the flow path and the login path fail rather than
         * report success.</p>
         */
        ERROR_PERSISTING_FED_ASSOCIATION("65014",
                "The Daon verification could not be recorded for the user.",
                "The Daon federated association could not be persisted because %s."),

        ERROR_READING_USER_CLAIMS("65015",
                "Could not read the user's stored claims.",
                "Error reading the invited user's stored claims for Daon verification; the "
                        + "corresponding claim value-requests will not be sent."),

        ERROR_BUILDING_CLAIMS_REQUEST("65017",
                "Could not build the Daon claims request.",
                "Error building the OIDC claims request parameter for the Daon authorization request."),

        ERROR_BUILDING_PORTAL_URL("65018",
                "Could not build the flow portal URL.",
                "Error building the portal URL for tenant: %s; falling back to the default portal URL."),

        ERROR_ACTIVATING_BUNDLE("65020",
                "Could not activate the Daon connector bundle.",
                "Error registering the Daon connector OSGi services; the bundle is active but one or "
                        + "more services may be unregistered."),

        /**
         * Daon returned a token without the verified-claims block, so nothing in the response evidences a
         * completed verification. The enrolment flows fail rather than continue: an empty verification
         * result must not be mistaken for a successful one.
         */
        ERROR_VERIFIED_CLAIMS_NOT_FOUND("65021",
                "Daon did not return any verified identity claims.",
                "The Daon ID token for the %s flow carries no 'verifiedClaims' (or no nested 'claims') "
                        + "object, so the verification cannot be treated as successful."),

        ERROR_TRUST_FRAMEWORK_MISMATCH("65022",
                "Daon verified the identity under an unexpected trust framework.",
                "The Daon ID token reports trust_framework '%s' but '%s' was requested; the verification "
                        + "does not meet the expected assurance."),

        ERROR_NO_VERIFIABLE_CLAIM_VALUES("65023",
                "There are no identity attributes to verify against the user's identity document. "
                        + "Check the Daon connection's attribute mappings.",
                "The %s flow sends the user's known attributes to Daon as OIDC claim value-requests, but "
                        + "none of the mapped attributes with a value is document-verifiable, so Daon "
                        + "would have nothing to validate the profile against."),

        ERROR_ENROL_PD_NOT_CONFIGURED("65024",
                "No Daon enrol process definition is configured.",
                "An enrolment was requested at the login step, but no enrol process definition could be "
                        + "resolved from the referenced Daon Identity Verifier connection."),

        ERROR_ENROLMENT_IDENTITY_NOT_RETURNED("65025",
                "Daon did not return an identity to enrol.",
                "The 'preferred_username' claim is not present in the Daon ID token returned for the "
                        + "enrolment, so there is no Daon subject to record for the user."),

        ERROR_READING_USER_CLAIMS_AT_LOGIN("65026",
                "Could not read the user's stored claims.",
                "Error reading the stored claims of the user being enrolled at the login step; the "
                        + "corresponding claim value-requests will not be sent to Daon.");

        private final String code;
        private final String message;
        private final String description;
        private final String i18nKey;

        ErrorMessage(String code, String message, String description) {

            this(code, message, description, null);
        }

        ErrorMessage(String code, String message, String description, String i18nKey) {

            this.code = code;
            this.message = message;
            this.description = description;
            this.i18nKey = i18nKey;
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

        /**
         * @return the flow portal resource bundle key, or {@code null} when this error is not user-facing.
         */
        public String getI18nKey() {

            return i18nKey;
        }

        /**
         * The heading the flow portal renders, as the {@code {{key}}} token that marks it user-facing.
         *
         * @return e.g. {@code {{daon.identity.verification.cancelled.message}}}, or {@code null} when this error
         *         has no user-facing wording and the portal should keep its own.
         */
        public String getUserMessageToken() {

            return i18nKey == null ? null : "{{" + i18nKey + ".message}}";
        }

        /**
         * The body the flow portal renders, as the {@code {{key}}} token that marks it user-facing.
         *
         * @return e.g. {@code {{daon.identity.verification.cancelled.description}}}, or {@code null} when this
         *         error has no user-facing wording.
         */
        public String getUserDescriptionToken() {

            return i18nKey == null ? null : "{{" + i18nKey + ".description}}";
        }

        @Override
        public String toString() {

            return getCode() + " - " + message;
        }
    }
}
