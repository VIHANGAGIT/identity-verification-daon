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
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;

import java.util.HashSet;
import java.util.Set;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
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
     * DAON-60001 is a published contract: the recovery portal and the login retry page switch on it.
     */
    @Test
    public void testUserNotEnrolledCodeIsStable() {

        assertEquals(ErrorMessage.ERROR_USER_NOT_ENROLLED.getCode(), "DAON-60001");
        assertEquals(DaonConstants.USER_NOT_ENROLLED_ERROR_CODE, "DAON-60001");
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
    public void testHandleClientException() {

        DaonClientException e = DaonExceptionMgt.handleClientException(
                ErrorMessage.ERROR_INVALID_VERIFICATION_FLOW_STATUS, "BOGUS");

        assertEquals(e.getErrorCode(), "DAON-60007");
        assertTrue(e.getMessage().contains("BOGUS"), e.getMessage());
    }

    @Test
    public void testHandleFlowServerException() {

        FlowEngineServerException e = DaonExceptionMgt.handleFlowServerException(
                ErrorMessage.ERROR_ID_TOKEN_NOT_FOUND, "REGISTRATION");

        assertEquals(e.getErrorCode(), "DAON-65002");
        assertEquals(e.getMessage(), ErrorMessage.ERROR_ID_TOKEN_NOT_FOUND.getMessage());
        assertTrue(e.getDescription().contains("REGISTRATION"), e.getDescription());
    }

    @Test
    public void testHandleFlowClientException() {

        FlowEngineClientException e = DaonExceptionMgt.handleFlowClientException(
                ErrorMessage.ERROR_RECOVERY_IDENTITY_MISMATCH, "alice@example.com");

        assertEquals(e.getErrorCode(), "DAON-60006");
        assertTrue(e.getDescription().contains("alice@example.com"), e.getDescription());
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
