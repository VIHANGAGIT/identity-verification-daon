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

package org.wso2.carbon.identity.verification.daon.connector;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIMS_PARAM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_DOCUMENT_CLASSIFICATION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_DOCUMENT_DATE_OF_EXPIRY;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_DOCUMENT_NUMBER;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_DOCUMENT_PERSONAL_NUMBER;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_DOCUMENT_TYPE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_FAMILY_NAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_FAMILY_NAME_AND_GIVEN_NAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_GIVEN_NAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_VALUE_MEMBER;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ID_TOKEN_CONTAINER;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.TRUST_FRAMEWORK;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.TRUST_FRAMEWORK_VALUE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.VERIFICATION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.VERIFIED_CLAIMS;

/**
 * Builds the OIDC {@code claims} request parameter Daon expects for identity verification.
 *
 * <p>This is the one part of the Daon authorize request that is not standard OIDC — everything else
 * (client id, endpoints, scope, state, nonce, redirect URI) is built by the OIDC authenticator/executor
 * this connector extends. The parameter is passed to Daon as an additional query parameter.</p>
 */
final class DaonClaimsRequestBuilder {

    /**
     * Document claims always requested alongside the mapped claims, so the verified document details are
     * returned regardless of the connection's claim configuration.
     */
    private static final List<String> DOCUMENT_CLAIMS = Arrays.asList(
            CLAIM_DOCUMENT_TYPE,
            CLAIM_DOCUMENT_CLASSIFICATION,
            CLAIM_DOCUMENT_DATE_OF_EXPIRY,
            CLAIM_DOCUMENT_NUMBER,
            CLAIM_DOCUMENT_PERSONAL_NUMBER
    );

    private DaonClaimsRequestBuilder() {
    }

    /**
     * Builds the OIDC {@code claims} request parameter JSON for the given Daon claim names.
     *
     * <p>If the list contains {@code given_name} or {@code family_name},
     * {@code family_name_and_given_name} is automatically added as a fallback. Some identity
     * documents store the full name as a single field; without this fallback Daon would return
     * neither name claim for those documents.
     *
     * <p>When a claim's value is already known before Daon is triggered (e.g. an attribute the user
     * populated earlier in a registration flow), it is sent as an OIDC value-request
     * ({@code {"value": "..."}}) instead of {@code null}, so Daon verifies against that value.</p>
     *
     * <pre>
     * {
     *   "id_token": {
     *     "verified_claims": {
     *       "verification": { "trust_framework": "daon-identify-1" },
     *       "claims": { "given_name": {"value": "JOHN"}, "family_name": null, ... }
     *     }
     *   }
     * }
     * </pre>
     *
     * @param daonClaimNames Daon claim names to request.
     * @param claimValues    Pre-known values keyed by Daon claim name; may be empty.
     */
    static String buildClaimsParam(List<String> daonClaimNames, Map<String, String> claimValues) {

        Map<String, String> values = claimValues != null ? claimValues : Collections.emptyMap();
        List<String> effectiveNames = new ArrayList<>(daonClaimNames);
        if ((effectiveNames.contains(CLAIM_GIVEN_NAME) || effectiveNames.contains(CLAIM_FAMILY_NAME))
                && !effectiveNames.contains(CLAIM_FAMILY_NAME_AND_GIVEN_NAME)) {
            effectiveNames.add(CLAIM_FAMILY_NAME_AND_GIVEN_NAME);
        }
        for (String docClaim : DOCUMENT_CLAIMS) {
            if (!effectiveNames.contains(docClaim)) {
                effectiveNames.add(docClaim);
            }
        }

        JSONObject claimsObj = new JSONObject();
        for (String claimName : effectiveNames) {
            String value = values.get(claimName);
            if (value != null && !value.trim().isEmpty()) {
                claimsObj.put(claimName, new JSONObject().put(CLAIM_VALUE_MEMBER, value));
            } else {
                claimsObj.put(claimName, JSONObject.NULL);
            }
        }
        JSONObject verification = new JSONObject().put(TRUST_FRAMEWORK, TRUST_FRAMEWORK_VALUE);
        JSONObject verifiedClaims = new JSONObject()
                .put(VERIFICATION, verification)
                .put(CLAIMS_PARAM, claimsObj);
        JSONObject idToken = new JSONObject().put(VERIFIED_CLAIMS, verifiedClaims);
        return new JSONObject().put(ID_TOKEN_CONTAINER, idToken).toString();
    }
}
