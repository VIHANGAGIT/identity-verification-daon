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

package org.wso2.carbon.identity.verification.daon.connector.exception;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;

import java.util.HashSet;
import java.util.Set;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;

/**
 * Tests the Daon error catalogue and the exception/log builders over it.
 */
public class DaonExceptionMgtTest {

    @Test
    public void testCodesArePrefixed() {

        for (ErrorMessage error : ErrorMessage.values()) {
            assertTrue(error.getCode().startsWith(DaonErrorConstants.DAON_ERROR_PREFIX),
                    error.name() + " does not carry the DAON- prefix: " + error.getCode());
        }
    }

    @Test
    public void testCodesAreUnique() {

        Set<String> seen = new HashSet<>();
        for (ErrorMessage error : ErrorMessage.values()) {
            assertTrue(seen.add(error.getCode()), "Duplicate error code: " + error.getCode());
        }
    }

    /**
     * Client errors live in the 60xxx band and server errors in 65xxx, matching the convention the rest of
     * the connector pack follows.
     */
    @Test
    public void testCodesUseTheClientServerBands() {

        for (ErrorMessage error : ErrorMessage.values()) {
            String digits = error.getCode().substring(DaonErrorConstants.DAON_ERROR_PREFIX.length());
            assertTrue(digits.matches("6[0-9]{4}"),
                    error.name() + " has a code outside the 6xxxx range: " + digits);
        }
    }

    @Test
    public void testMessagesAndDescriptionsArePresent() {

        for (ErrorMessage error : ErrorMessage.values()) {
            assertNotNull(error.getMessage(), error.name() + " has no message.");
            assertNotNull(error.getDescription(), error.name() + " has no description.");
        }
    }

    /**
     * DAON-60001 is what an adaptive script's onFail handler keys off to route a not-enrolled user into
     * enrolment, so the literal is a published contract with every such script.
     */
    @Test
    public void testUserNotEnrolledCodeIsStable() {

        assertEquals(ErrorMessage.ERROR_USER_NOT_ENROLLED.getCode(), "DAON-60001");
    }

    @Test
    public void testToStringCarriesThePrefixedCode() {

        assertEquals(ErrorMessage.ERROR_ID_TOKEN_NOT_FOUND.toString(),
                "DAON-65002 - " + ErrorMessage.ERROR_ID_TOKEN_NOT_FOUND.getMessage());
    }

    @Test
    public void testDescriptionIsFormattedWithData() {

        String log = DaonExceptionMgt.errorLog(ErrorMessage.ERROR_RESOLVING_REFERENCED_IDP, "idp-uuid-1");
        assertTrue(log.startsWith("DAON-65008 - "), log);
        assertTrue(log.contains("idp-uuid-1"), log);
    }

    /**
     * With no arguments the template must be returned verbatim rather than half-formatted, so an unfilled
     * {@code %s} never reaches a log or a client.
     */
    @Test
    public void testDescriptionIsLeftUnformattedWithoutData() {

        String log = DaonExceptionMgt.errorLog(ErrorMessage.ERROR_RESOLVING_REFERENCED_IDP);
        assertEquals(log, "DAON-65008 - " + ErrorMessage.ERROR_RESOLVING_REFERENCED_IDP.getDescription());
    }

    @Test
    public void testHandleServerException() {

        Throwable cause = new IllegalStateException("boom");
        DaonServerException e =
                DaonExceptionMgt.handleServerException(ErrorMessage.ERROR_DECODING_ID_TOKEN, cause);

        assertEquals(e.getErrorCode(), "DAON-65004");
        assertEquals(e.getMessage(), ErrorMessage.ERROR_DECODING_ID_TOKEN.getDescription());
        assertSame(e.getCause(), cause);
    }

    @Test
    public void testHandleFlowServerException() {

        FlowEngineServerException e = DaonExceptionMgt.handleFlowServerException(
                ErrorMessage.ERROR_ID_TOKEN_NOT_FOUND, "REGISTRATION");

        assertEquals(e.getErrorCode(), "DAON-65002");
        assertEquals(e.getMessage(), ErrorMessage.ERROR_ID_TOKEN_NOT_FOUND.getMessage());
        assertTrue(e.getDescription().contains("REGISTRATION"), e.getDescription());
    }

    /**
     * A client failure is rendered to the end user, so it must carry the portal's i18n tokens and nothing
     * else: the diagnostic description names the account being recovered and must not cross to the browser.
     */
    @Test
    public void testHandleFlowClientExceptionCarriesI18nTokensOnly() {

        FlowEngineClientException e = DaonExceptionMgt.handleFlowClientException(
                ErrorMessage.ERROR_RECOVERY_IDENTITY_MISMATCH);

        assertEquals(e.getErrorCode(), "DAON-60006");
        assertEquals(e.getMessage(), "{{daon.identity.verification.identity.mismatch.message}}");
        assertEquals(e.getDescription(), "{{daon.identity.verification.identity.mismatch.description}}");
    }

    /**
     * An error with no i18n key is not user-facing. It must not produce a token, or the portal would render
     * an unresolvable key in place of its own flow-type wording.
     */
    @Test
    public void testServerErrorsCarryNoUserFacingToken() {

        assertNull(ErrorMessage.ERROR_ID_TOKEN_NOT_FOUND.getUserMessageToken());
        assertNull(ErrorMessage.ERROR_ID_TOKEN_NOT_FOUND.getUserDescriptionToken());
        assertEquals(DaonExceptionMgt.userMessage(ErrorMessage.ERROR_ID_TOKEN_NOT_FOUND),
                ErrorMessage.ERROR_ID_TOKEN_NOT_FOUND.getMessage());
    }

    /**
     * Every failure a flow can show the end user must name a key the portal resolves; without one the page
     * falls back to generic wording and the reason is lost.
     */
    @Test
    public void testUserFacingClientErrorsNameAnI18nKey() {

        ErrorMessage[] userFacing = {
                ErrorMessage.ERROR_USER_NOT_ENROLLED,
                ErrorMessage.ERROR_VERIFICATION_CANCELLED,
                ErrorMessage.ERROR_CLAIMS_VERIFICATION_MISMATCH,
                ErrorMessage.ERROR_IDENTITY_VERIFICATION_FAILED,
                ErrorMessage.ERROR_VERIFICATION_NOT_COMPLETED,
                ErrorMessage.ERROR_RECOVERY_IDENTITY_MISMATCH
        };

        for (ErrorMessage error : userFacing) {
            assertNotNull(error.getI18nKey(), error.name() + " must name an i18n key.");
            assertEquals(error.getUserMessageToken(), "{{" + error.getI18nKey() + ".message}}");
            assertEquals(error.getUserDescriptionToken(), "{{" + error.getI18nKey() + ".description}}");
        }
    }

    /**
     * The 65xxx band is administrator-facing by construction; a key there would put text like "check the
     * verifier id it references" in front of an end user.
     */
    @Test
    public void testServerErrorBandHasNoI18nKeys() {

        for (ErrorMessage error : ErrorMessage.values()) {
            if (error.getCode().startsWith(DaonErrorConstants.DAON_ERROR_PREFIX + "65")) {
                assertNull(error.getI18nKey(), error.name() + " is a server error and must not be shown.");
            }
        }
    }

    /**
     * The code raised at the point of failure must survive the hop into the flow engine — the parent
     * OpenIDConnectExecutor helper would replace it with the engine's own generic code.
     */
    @Test
    public void testToFlowServerExceptionPreservesTheOriginalCode() {

        DaonServerException original =
                DaonExceptionMgt.handleServerException(ErrorMessage.ERROR_INVALID_ID_TOKEN, 1);
        FlowEngineServerException converted = DaonExceptionMgt.toFlowServerException(original);

        assertEquals(converted.getErrorCode(), "DAON-65003");
        assertSame(converted.getCause(), original);
    }

    @Test
    public void testHandleAuthFailedExceptionCarriesCodeAndUserFacingMessage() {

        AuthenticationFailedException e =
                DaonExceptionMgt.handleAuthFailedException(ErrorMessage.ERROR_USER_NOT_ENROLLED);

        assertEquals(e.getErrorCode(), "DAON-60001");
        assertEquals(e.getMessage(), ErrorMessage.ERROR_USER_NOT_ENROLLED.getMessage());
    }
}
