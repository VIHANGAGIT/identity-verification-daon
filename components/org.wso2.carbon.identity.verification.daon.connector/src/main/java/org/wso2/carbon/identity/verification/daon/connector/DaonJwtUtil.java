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

import org.json.JSONObject;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Shared utilities for decoding Daon JWT payloads and resolving claim values.
 */
final class DaonJwtUtil {

    private DaonJwtUtil() {}

    /**
     * Base64URL-decodes the payload segment of a JWT and returns it as a {@link JSONObject}.
     *
     * @throws IllegalArgumentException if the JWT has fewer than 2 segments or the payload cannot be decoded
     */
    static JSONObject decodeJwtPayload(String idToken) {
        String[] parts = idToken.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException(
                    "Invalid JWT: expected at least 2 segments, got " + parts.length);
        }
        try {
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            return new JSONObject(new String(payload, StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to decode Daon ID token payload", e);
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
    static String resolveClaimValue(String key, Object value) {
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
}
