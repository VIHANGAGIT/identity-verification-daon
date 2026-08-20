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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;

import static org.testng.Assert.assertEquals;

/**
 * Tests the mapping from a Daon OAuth2 error callback to a coded error.
 */
public class DaonCallbackErrorsTest {

    @DataProvider(name = "callbackErrors")
    public Object[][] callbackErrors() {

        return new Object[][]{
                {"access_denied", null, ErrorMessage.ERROR_VERIFICATION_CANCELLED},
                {"ACCESS_DENIED", "", ErrorMessage.ERROR_VERIFICATION_CANCELLED},
                {"  access_denied  ", null, ErrorMessage.ERROR_VERIFICATION_CANCELLED},
                {"FailedToVerifyUser", null, ErrorMessage.ERROR_IDENTITY_VERIFICATION_FAILED},
                {"failedtoverifyuser", "[\"SOME_OTHER_REASON\"]",
                        ErrorMessage.ERROR_IDENTITY_VERIFICATION_FAILED},
                // Daon sends the reason as a JSON array; matched as a substring.
                {"FailedToVerifyUser", "[\"CLAIMS_VERIFICATION_MISMATCH\"]",
                        ErrorMessage.ERROR_CLAIMS_VERIFICATION_MISMATCH},
                {null, "[\"CLAIMS_VERIFICATION_MISMATCH\"]",
                        ErrorMessage.ERROR_CLAIMS_VERIFICATION_MISMATCH},
                {"server_error", null, ErrorMessage.ERROR_VERIFICATION_NOT_COMPLETED},
                {null, null, ErrorMessage.ERROR_VERIFICATION_NOT_COMPLETED},
        };
    }

    @Test(dataProvider = "callbackErrors")
    public void testResolveError(String error, String errorDescription, ErrorMessage expected) {

        assertEquals(DaonCallbackErrors.resolveError(error, errorDescription), expected);
    }

    /**
     * The mismatch reason must win over the accompanying FailedToVerifyUser code, so the user is told
     * their details did not match rather than the generic "could not be verified".
     */
    @Test
    public void testMismatchReasonTakesPrecedenceOverErrorCode() {

        assertEquals(
                DaonCallbackErrors.resolveError("FailedToVerifyUser", "[\"CLAIMS_VERIFICATION_MISMATCH\"]"),
                ErrorMessage.ERROR_CLAIMS_VERIFICATION_MISMATCH);
    }

    /**
     * access_denied is checked first, so a cancellation stays a cancellation even if Daon also reports a
     * mismatch reason.
     */
    @Test
    public void testCancellationTakesPrecedenceOverMismatchReason() {

        assertEquals(
                DaonCallbackErrors.resolveError("access_denied", "[\"CLAIMS_VERIFICATION_MISMATCH\"]"),
                ErrorMessage.ERROR_VERIFICATION_CANCELLED);
    }
}
