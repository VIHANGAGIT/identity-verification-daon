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
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

/**
 * Tests the extraction of Daon's verified claims from an ID token payload — in particular that a token
 * carrying no verification result fails the flow instead of passing as a successful verification — and the
 * matching of the identity the token carries against the subject a flow expects.
 */
public class DaonJwtUtilTest {

    private static final String FLOW_TYPE = "REGISTRATION";

    private JSONObject payloadWith(JSONObject verifiedClaims) {

        JSONObject payload = new JSONObject().put(DaonConstants.JWT_SUBJECT_CLAIM, "daon-sub");
        if (verifiedClaims != null) {
            payload.put(DaonConstants.JWT_VERIFIED_CLAIMS_OBJECT, verifiedClaims);
        }
        return payload;
    }

    private JSONObject verifiedClaims(String trustFramework, JSONObject claims) {

        JSONObject verifiedClaims = new JSONObject();
        if (trustFramework != null) {
            verifiedClaims.put(DaonConstants.VERIFICATION,
                    new JSONObject().put(DaonConstants.TRUST_FRAMEWORK, trustFramework));
        }
        if (claims != null) {
            verifiedClaims.put(DaonConstants.JWT_CLAIMS_OBJECT, claims);
        }
        return verifiedClaims;
    }

    @Test
    public void testExtractsClaimsWithRequestedTrustFramework() throws Exception {

        JSONObject claims = new JSONObject().put(DaonConstants.CLAIM_GIVEN_NAME, "JOHN");
        JSONObject payload =
                payloadWith(verifiedClaims(DaonConstants.TRUST_FRAMEWORK_VALUE, claims));

        JSONObject extracted = DaonJwtUtil.extractVerifiedClaims(payload, FLOW_TYPE);

        assertEquals(extracted.getString(DaonConstants.CLAIM_GIVEN_NAME), "JOHN");
    }

    /**
     * Whether a Daon tenant echoes the verification descriptor back is tenant-configuration dependent, so
     * its absence must not fail an otherwise complete verification result.
     */
    @Test
    public void testExtractsClaimsWhenVerificationDescriptorAbsent() throws Exception {

        JSONObject claims = new JSONObject().put(DaonConstants.CLAIM_GIVEN_NAME, "JOHN");
        JSONObject extracted =
                DaonJwtUtil.extractVerifiedClaims(payloadWith(verifiedClaims(null, claims)), FLOW_TYPE);

        assertEquals(extracted.getString(DaonConstants.CLAIM_GIVEN_NAME), "JOHN");
    }

    /**
     * A verification carried out under a framework other than the one requested does not carry the
     * assurance that was asked for.
     */
    @Test
    public void testRejectsUnexpectedTrustFramework() {

        JSONObject payload = payloadWith(verifiedClaims("some-other-framework",
                new JSONObject().put(DaonConstants.CLAIM_GIVEN_NAME, "JOHN")));

        DaonServerException e = expectThrows(DaonServerException.class,
                () -> DaonJwtUtil.extractVerifiedClaims(payload, FLOW_TYPE));
        assertEquals(e.getErrorCode(), "DAON-65022");
        assertTrue(e.getMessage().contains("some-other-framework"));
    }

    @Test
    public void testFailsWhenVerifiedClaimsObjectMissing() {

        DaonServerException e = expectThrows(DaonServerException.class,
                () -> DaonJwtUtil.extractVerifiedClaims(payloadWith(null), FLOW_TYPE));
        assertEquals(e.getErrorCode(), "DAON-65021");
        assertTrue(e.getMessage().contains(FLOW_TYPE));
    }

    @Test
    public void testFailsWhenNestedClaimsObjectMissing() {

        JSONObject payload =
                payloadWith(verifiedClaims(DaonConstants.TRUST_FRAMEWORK_VALUE, null));

        DaonServerException e = expectThrows(DaonServerException.class,
                () -> DaonJwtUtil.extractVerifiedClaims(payload, FLOW_TYPE));
        assertEquals(e.getErrorCode(), "DAON-65021");
    }

    @Test
    public void testFailsWhenVerifiedClaimsIsNotAnObject() {

        JSONObject payload = new JSONObject()
                .put(DaonConstants.JWT_VERIFIED_CLAIMS_OBJECT, "not-an-object");

        assertEquals(expectThrows(DaonServerException.class,
                () -> DaonJwtUtil.extractVerifiedClaims(payload, FLOW_TYPE)).getErrorCode(),
                "DAON-65021");
    }

    @Test
    public void testFailsOnNullPayload() {

        assertEquals(expectThrows(DaonServerException.class,
                () -> DaonJwtUtil.extractVerifiedClaims(null, FLOW_TYPE)).getErrorCode(),
                "DAON-65021");
    }

    @Test
    public void testDecodeMalformedJwtIsReported() {

        assertEquals(expectThrows(DaonServerException.class,
                () -> DaonJwtUtil.decodeJwtPayload("only-one-segment")).getErrorCode(), "DAON-65003");
        assertEquals(expectThrows(DaonServerException.class,
                () -> DaonJwtUtil.decodeJwtPayload("header.!!not-base64!!.sig")).getErrorCode(),
                "DAON-65004");
    }

    @Test
    public void testResolveClaimValueFlattensAddress() {

        JSONObject address = new JSONObject().put(DaonConstants.CLAIM_ADDRESS_FORMATTED, "1 Main St");

        assertEquals(DaonJwtUtil.resolveClaimValue(DaonConstants.CLAIM_ADDRESS, address), "1 Main St");
        assertEquals(DaonJwtUtil.resolveClaimValue(DaonConstants.CLAIM_GIVEN_NAME, "JOHN"), "JOHN");
        assertNull(DaonJwtUtil.resolveClaimValue(DaonConstants.CLAIM_GIVEN_NAME, JSONObject.NULL));
        assertNull(DaonJwtUtil.resolveClaimValue(DaonConstants.CLAIM_GIVEN_NAME, null));
    }

    /**
     * The following cover the binding of the identity Daon verified to the account being verified. This is
     * the check that stops a user who verifies their own enrolled Daon identity from satisfying the
     * verification step for somebody else's account, so the fail-closed cases matter as much as the
     * matching ones.
     */
    @DataProvider(name = "matchingIdentities")
    public Object[][] matchingIdentities() {

        return new Object[][]{
                // The enrolled identity comes back as preferred_username.
                {"daon-user-1", "daon-user-1"},
                // Case and surrounding whitespace are not significant.
                {"Daon-User-1", "daon-user-1"},
                {"  daon-user-1  ", "daon-user-1"},
                {"daon-user-1", "  daon-user-1  "},
        };
    }

    @Test(dataProvider = "matchingIdentities")
    public void testMatchesExpectedIdentity(String expected, String returnedPreferredUsername) {

        assertTrue(DaonJwtUtil.isExpectedSubject(expected, returnedPreferredUsername));
    }

    @DataProvider(name = "nonMatchingIdentities")
    public Object[][] nonMatchingIdentities() {

        return new Object[][]{
                // The attack this check exists for: Daon verified a different enrolled user.
                {"daon-user-1", "daon-user-2"},
                // Partial overlaps are not matches.
                {"daon-user-1", "daon-user-10"},
                {"daon-user-1", "daon-user"},
                // Nothing returned at all.
                {"daon-user-1", null},
                {"daon-user-1", ""},
                {"daon-user-1", "   "},
        };
    }

    @Test(dataProvider = "nonMatchingIdentities")
    public void testRejectsUnexpectedIdentity(String expected, String returnedPreferredUsername) {

        assertFalse(DaonJwtUtil.isExpectedSubject(expected, returnedPreferredUsername));
    }

    /**
     * Fails closed: when the enrolled subject could not be resolved there is nothing to bind the response
     * to, so no returned identity — not even a blank one — may satisfy the check.
     */
    @DataProvider(name = "blankExpectedSubjects")
    public Object[][] blankExpectedSubjects() {

        return new Object[][]{{null}, {""}, {"   "}};
    }

    @Test(dataProvider = "blankExpectedSubjects")
    public void testBlankExpectedSubjectNeverMatches(String expected) {

        assertFalse(DaonJwtUtil.isExpectedSubject(expected, "daon-user-1"));
        assertFalse(DaonJwtUtil.isExpectedSubject(expected, expected));
    }
}
