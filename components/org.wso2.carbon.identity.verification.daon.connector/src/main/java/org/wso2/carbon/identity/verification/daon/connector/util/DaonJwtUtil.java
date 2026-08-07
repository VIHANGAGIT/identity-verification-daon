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

package org.wso2.carbon.identity.verification.daon.connector.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Shared utilities for decoding Daon JWT payloads, resolving claim values and matching the identity the
 * token carries against the one a flow expects.
 */
public final class DaonJwtUtil {

    private static final Log LOG = LogFactory.getLog(DaonJwtUtil.class);

    private DaonJwtUtil() {}

    /**
     * Base64URL-decodes the payload segment of a JWT and returns it as a {@link JSONObject}.
     *
     * @throws DaonServerException {@code DAON-65003} if the JWT has fewer than 2 segments,
     *                             {@code DAON-65004} if the payload cannot be decoded or parsed.
     */
    public static JSONObject decodeJwtPayload(String idToken) throws DaonServerException {
        String[] parts = idToken.split("\\.");
        if (parts.length < 2) {
            throw DaonExceptionMgt.handleServerException(ErrorMessage.ERROR_INVALID_ID_TOKEN, parts.length);
        }
        try {
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            return new JSONObject(new String(payload, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException | JSONException e) {
            // IllegalArgumentException: not valid Base64URL. JSONException: decoded bytes are not a JSON
            // object. Both mean the same thing to the caller — the ID token payload is unreadable.
            throw DaonExceptionMgt.handleServerException(ErrorMessage.ERROR_DECODING_ID_TOKEN, e);
        }
    }

    /**
     * Extracts the verified identity claims from a Daon ID token payload, failing when the response does
     * not evidence a completed verification.
     *
     * <p>Daon nests them as {@code verifiedClaims.claims}. Either level being absent means the token
     * carries no verification result: the enrolment flows must fail rather than continue, since an empty
     * result would otherwise be indistinguishable from a successful verification that returned nothing.</p>
     *
     * <p>When the payload also carries the {@code verification} descriptor, its {@code trust_framework} is
     * checked against the one requested in the {@code claims} parameter
     * ({@link DaonConstants#TRUST_FRAMEWORK_VALUE}) — a verification performed under a different framework
     * does not carry the assurance that was asked for. The descriptor is not required, because whether a
     * Daon tenant echoes it back is tenant-configuration dependent; when it is absent this logs and
     * proceeds on the {@code claims} block alone.</p>
     *
     * @param idTokenPayload decoded ID token payload.
     * @param flowType       flow the token was obtained for; used in the error description.
     * @return the {@code claims} object holding the verified attributes; never {@code null}.
     * @throws DaonServerException {@code DAON-65021} if the verified-claims block is missing,
     *                             {@code DAON-65022} if the trust framework is not the requested one.
     */
    public static JSONObject extractVerifiedClaims(JSONObject idTokenPayload, String flowType)
            throws DaonServerException {

        if (idTokenPayload == null || !idTokenPayload.has(DaonConstants.JWT_VERIFIED_CLAIMS_OBJECT)) {
            throw DaonExceptionMgt.handleServerException(ErrorMessage.ERROR_VERIFIED_CLAIMS_NOT_FOUND,
                    flowType);
        }
        JSONObject verifiedClaims = idTokenPayload.optJSONObject(DaonConstants.JWT_VERIFIED_CLAIMS_OBJECT);
        if (verifiedClaims == null) {
            throw DaonExceptionMgt.handleServerException(ErrorMessage.ERROR_VERIFIED_CLAIMS_NOT_FOUND,
                    flowType);
        }
        validateTrustFramework(verifiedClaims);
        JSONObject claims = verifiedClaims.optJSONObject(DaonConstants.JWT_CLAIMS_OBJECT);
        if (claims == null) {
            throw DaonExceptionMgt.handleServerException(ErrorMessage.ERROR_VERIFIED_CLAIMS_NOT_FOUND,
                    flowType);
        }
        return claims;
    }

    /**
     * Fails when the returned {@code verification.trust_framework} is present but is not the framework the
     * {@code claims} request asked Daon to verify under. An absent descriptor is logged and allowed
     * through — see {@link #extractVerifiedClaims}.
     */
    private static void validateTrustFramework(JSONObject verifiedClaims) throws DaonServerException {

        JSONObject verification = verifiedClaims.optJSONObject(DaonConstants.VERIFICATION);
        String trustFramework = verification != null
                ? verification.optString(DaonConstants.TRUST_FRAMEWORK, null) : null;
        if (trustFramework == null) {
            LOG.debug("The Daon ID token carries no verification.trust_framework descriptor; accepting the "
                    + "verified claims on the 'claims' object alone.");
            return;
        }
        if (!DaonConstants.TRUST_FRAMEWORK_VALUE.equals(trustFramework)) {
            throw DaonExceptionMgt.handleServerException(ErrorMessage.ERROR_TRUST_FRAMEWORK_MISMATCH,
                    trustFramework, DaonConstants.TRUST_FRAMEWORK_VALUE);
        }
    }

    /**
     * Resolves a claim value to a plain string.
     *
     * <ul>
     *   <li>The {@code address} claim, which Daon represents as {@code {"formatted": "..."}},
     *       is flattened to its {@code formatted} field.</li>
     *   <li>Other nested JSON objects are returned as their JSON string representation.</li>
     *   <li>Primitive values are converted via {@code toString()}.</li>
     *   <li>Null or {@link JSONObject#NULL} values return {@code null}.</li>
     * </ul>
     */
    public static String resolveClaimValue(String key, Object value) {
        if (value == null || JSONObject.NULL.equals(value)) {
            return null;
        }
        if (value instanceof JSONObject) {
            JSONObject nested = (JSONObject) value;
            if (DaonConstants.CLAIM_ADDRESS.equals(key)
                    && nested.has(DaonConstants.CLAIM_ADDRESS_FORMATTED)) {
                Object formatted = nested.get(DaonConstants.CLAIM_ADDRESS_FORMATTED);
                return formatted != null && !JSONObject.NULL.equals(formatted) ? formatted.toString() : null;
            }
            return nested.toString();
        }
        return value.toString();
    }

    /**
     * Checks whether the identity Daon returned is the expected one.
     *
     * <p>{@code login_hint} is only a hint per OIDC — Daon verifies whoever presents themselves, not
     * necessarily the account holder named in the hint. Every flow that re-verifies an <b>already
     * enrolled</b> user (the login step in {@code DaonAuthenticator} and password recovery in
     * {@code DaonExecutor}) therefore has to compare the identity in the returned ID token against the Daon
     * subject recorded in that user's federated association. Without this check, anyone who completes a
     * Daon verification with their own enrolled account satisfies the identity-proofing step for any other
     * user. Both flows call this so they apply the same comparison rules.</p>
     *
     * <p>The compared value is {@code preferred_username}: Daon identifies the verified user by that claim
     * and it is the value recorded in the association at enrolment. Comparison is case-insensitive and
     * ignores surrounding whitespace.</p>
     *
     * <p><b>Fails closed:</b> a blank expected subject matches nothing, so a caller that could not resolve
     * the enrolled subject can never accidentally pass the check. A blank returned value never matches.</p>
     *
     * @param expectedSubject           the Daon subject recorded in the user's federated association.
     * @param returnedPreferredUsername the {@code preferred_username} from the returned ID token.
     * @return {@code true} only if both values are present and equal.
     */
    public static boolean isExpectedSubject(String expectedSubject, String returnedPreferredUsername) {

        if (StringUtils.isBlank(expectedSubject) || StringUtils.isBlank(returnedPreferredUsername)) {
            return false;
        }
        return expectedSubject.trim().equalsIgnoreCase(returnedPreferredUsername.trim());
    }
}
