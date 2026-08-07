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

package org.wso2.carbon.identity.verification.daon.connector.util;

import org.json.JSONObject;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Tests the OIDC {@code claims} request Daon is sent, and the check that decides whether that request can
 * actually validate a pre-populated profile.
 */
public class DaonClaimsRequestBuilderTest {

    private JSONObject claimsOf(String claimsParam) {

        return new JSONObject(claimsParam)
                .getJSONObject(DaonConstants.ID_TOKEN_CONTAINER)
                .getJSONObject(DaonConstants.VERIFIED_CLAIMS)
                .getJSONObject(DaonConstants.CLAIMS_PARAM);
    }

    @Test
    public void testKnownValuesAreSentAsValueRequests() throws Exception {

        Map<String, String> values = new HashMap<>();
        values.put(DaonConstants.CLAIM_GIVEN_NAME, "JOHN");

        JSONObject claims = claimsOf(DaonClaimsRequestBuilder.buildClaimsParam(
                Arrays.asList(DaonConstants.CLAIM_GIVEN_NAME, DaonConstants.CLAIM_FAMILY_NAME), values));

        assertEquals(claims.getJSONObject(DaonConstants.CLAIM_GIVEN_NAME)
                .getString(DaonConstants.CLAIM_VALUE_MEMBER), "JOHN");
        // A claim with no known value is requested without a value, so Daon returns it verified.
        assertTrue(claims.isNull(DaonConstants.CLAIM_FAMILY_NAME));
    }

    @Test
    public void testRequestedUnderTheExpectedTrustFramework() throws Exception {

        String claimsParam = DaonClaimsRequestBuilder.buildClaimsParam(
                Collections.singletonList(DaonConstants.CLAIM_GIVEN_NAME), Collections.emptyMap());

        assertEquals(new JSONObject(claimsParam)
                        .getJSONObject(DaonConstants.ID_TOKEN_CONTAINER)
                        .getJSONObject(DaonConstants.VERIFIED_CLAIMS)
                        .getJSONObject(DaonConstants.VERIFICATION)
                        .getString(DaonConstants.TRUST_FRAMEWORK),
                DaonConstants.TRUST_FRAMEWORK_VALUE);
    }

    @Test
    public void testNameFallbackAndDocumentClaimsAreAlwaysRequested() throws Exception {

        JSONObject claims = claimsOf(DaonClaimsRequestBuilder.buildClaimsParam(
                Collections.singletonList(DaonConstants.CLAIM_GIVEN_NAME), Collections.emptyMap()));

        assertTrue(claims.has(DaonConstants.CLAIM_FAMILY_NAME_AND_GIVEN_NAME));
        assertTrue(claims.has(DaonConstants.CLAIM_DOCUMENT_NUMBER));
        assertTrue(claims.has(DaonConstants.CLAIM_DOCUMENT_TYPE));
    }

    /**
     * An invited-user flow only proves something if Daon has a document field to compare a known value
     * with. These are the values that give it one.
     */
    @Test
    public void testDocumentVerifiableValuesAreRecognised() {

        assertTrue(DaonClaimsRequestBuilder.hasDocumentVerifiableValue(
                Collections.singletonMap(DaonConstants.CLAIM_GIVEN_NAME, "JOHN")));
        assertTrue(DaonClaimsRequestBuilder.hasDocumentVerifiableValue(
                Collections.singletonMap(DaonConstants.CLAIM_FAMILY_NAME, "SMITH")));
        assertTrue(DaonClaimsRequestBuilder.hasDocumentVerifiableValue(
                Collections.singletonMap(DaonConstants.CLAIM_FAMILY_NAME_AND_GIVEN_NAME, "SMITH^JOHN")));
        assertTrue(DaonClaimsRequestBuilder.hasDocumentVerifiableValue(
                Collections.singletonMap(DaonConstants.CLAIM_BIRTHDATE, "1990-01-01")));
        assertTrue(DaonClaimsRequestBuilder.hasDocumentVerifiableValue(
                Collections.singletonMap(DaonConstants.CLAIM_DOCUMENT_NUMBER, "P1234567")));
    }

    /**
     * Attributes that do not appear on an identity document verify nothing: a flow whose value-requests
     * are all of this kind would report success for any valid document, so it must not be treated as a
     * profile validation.
     */
    @Test
    public void testNonDocumentAttributesDoNotCount() {

        Map<String, String> contactOnly = new HashMap<>();
        contactOnly.put("email", "john@example.com");
        contactOnly.put("phone_number", "+15550100");

        assertFalse(DaonClaimsRequestBuilder.hasDocumentVerifiableValue(contactOnly));
    }

    @Test
    public void testBlankAndEmptyValuesDoNotCount() {

        assertFalse(DaonClaimsRequestBuilder.hasDocumentVerifiableValue(
                Collections.singletonMap(DaonConstants.CLAIM_GIVEN_NAME, "   ")));
        assertFalse(DaonClaimsRequestBuilder.hasDocumentVerifiableValue(Collections.emptyMap()));
        assertFalse(DaonClaimsRequestBuilder.hasDocumentVerifiableValue(null));
    }
}
