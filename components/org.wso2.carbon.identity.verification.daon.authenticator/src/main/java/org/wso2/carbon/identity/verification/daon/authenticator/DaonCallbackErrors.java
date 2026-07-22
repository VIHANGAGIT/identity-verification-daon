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
 * <p>Handling is intentionally <b>generic</b>: only the standard OAuth2 error codes are interpreted, so no
 * Daon-specific vocabulary is required. Callers log the raw {@code error}/{@code error_description} for
 * diagnostics; once Daon's specific verification-failure codes are known from those logs, tailored mappings
 * can be added here in one place (e.g. distinct messages for liveness, face-match or document failures).</p>
 */
final class DaonCallbackErrors {

    /** Standard OAuth2 error code emitted when the user cancels or declines the verification. */
    private static final String ERROR_ACCESS_DENIED = "access_denied";

    private DaonCallbackErrors() {
    }

    /**
     * Resolves a user-facing message for a Daon OAuth2 error callback. The raw {@code error} /
     * {@code errorDescription} are not surfaced to the end user (they are logged by the caller); this
     * returns a safe, generic message keyed off the standard error code.
     *
     * @param error            the standard OAuth2 {@code error} code (may be blank).
     * @param errorDescription the OAuth2 {@code error_description} (currently unused in the message, kept
     *                         for future Daon-specific mapping and to document the contract).
     * @return a user-facing message describing the failure.
     */
    static String resolveUserFacingMessage(String error, String errorDescription) {

        if (ERROR_ACCESS_DENIED.equalsIgnoreCase(StringUtils.trimToEmpty(error))) {
            return "Identity verification was cancelled or not completed. Please try again.";
        }
        return "Identity verification could not be completed. Please try again or contact support.";
    }
}
