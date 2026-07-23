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

package org.wso2.carbon.identity.verification.daon.authenticator;

import org.apache.commons.lang.StringUtils;

/**
 * Maps the standard OAuth2/OIDC {@code error} returned by Daon on the authorization callback to a clean,
 * user-facing message. Both the login authenticator and the flow executor use this so error handling stays
 * consistent across flows.
 *
 * <p>Standard OAuth2 codes (e.g. {@code access_denied}) are interpreted generically; known Daon-specific
 * codes/reason tokens (e.g. {@code FailedToVerifyUser} / {@code CLAIMS_VERIFICATION_MISMATCH}) get tailored
 * messages. Callers log the raw {@code error}/{@code error_description} for diagnostics; further Daon
 * verification-failure reasons (liveness, face-match, document) can be mapped here in one place as they
 * surface in those logs.</p>
 */
final class DaonCallbackErrors {

    /** Standard OAuth2 error code emitted when the user cancels or declines the verification. */
    private static final String ERROR_ACCESS_DENIED = "access_denied";

    /**
     * Daon {@code error} code returned on the callback when it could not verify the user — including when
     * the pre-filled attribute values sent as OIDC claim value-requests do not match the identity document.
     */
    private static final String ERROR_FAILED_TO_VERIFY_USER = "FailedToVerifyUser";

    /**
     * Daon reason token carried inside {@code error_description} (a JSON array, e.g.
     * {@code ["CLAIMS_VERIFICATION_MISMATCH"]}) when the verified claims did not match the values Daon was
     * asked to verify against. Matched as a substring so the surrounding array/quoting is irrelevant.
     */
    private static final String REASON_CLAIMS_VERIFICATION_MISMATCH = "CLAIMS_VERIFICATION_MISMATCH";

    private DaonCallbackErrors() {
    }

    /**
     * Resolves a user-facing message for a Daon OAuth2 error callback. The raw {@code error} /
     * {@code errorDescription} are not surfaced to the end user (they are logged by the caller); this
     * returns a safe, generic message keyed off the standard error code.
     *
     * @param error            the standard OAuth2 {@code error} code (may be blank).
     * @param errorDescription the OAuth2 {@code error_description}; inspected for Daon reason tokens (e.g.
     *                         {@code CLAIMS_VERIFICATION_MISMATCH}) to tailor the message. Never surfaced
     *                         to the end user verbatim.
     * @return a user-facing message describing the failure.
     */
    static String resolveUserFacingMessage(String error, String errorDescription) {

        String normalizedError = StringUtils.trimToEmpty(error);
        String normalizedDescription = StringUtils.trimToEmpty(errorDescription);

        if (ERROR_ACCESS_DENIED.equalsIgnoreCase(normalizedError)) {
            return "Identity verification was cancelled or not completed. Please try again.";
        }
        // The details submitted (e.g. the pre-filled name/date of birth sent as claim value-requests) did
        // not match the identity document. The reason is carried in error_description; key off it directly
        // so the message stays correct regardless of the accompanying error code.
        if (normalizedDescription.toLowerCase().contains(REASON_CLAIMS_VERIFICATION_MISMATCH.toLowerCase())) {
            return "The details you entered do not match your identity document. " +
                    "Please check your information and try again.";
        }
        if (ERROR_FAILED_TO_VERIFY_USER.equalsIgnoreCase(normalizedError)) {
            return "Your identity could not be verified. Please try again or contact support.";
        }
        return "Identity verification could not be completed. Please try again or contact support.";
    }
}
