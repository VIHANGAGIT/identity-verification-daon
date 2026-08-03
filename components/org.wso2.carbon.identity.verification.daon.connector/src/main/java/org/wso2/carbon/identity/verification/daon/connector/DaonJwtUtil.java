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

import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;

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
     * @throws DaonServerException {@code DAON-65003} if the JWT has fewer than 2 segments,
     *                             {@code DAON-65004} if the payload cannot be decoded or parsed.
     */
    static JSONObject decodeJwtPayload(String idToken) throws DaonServerException {
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
