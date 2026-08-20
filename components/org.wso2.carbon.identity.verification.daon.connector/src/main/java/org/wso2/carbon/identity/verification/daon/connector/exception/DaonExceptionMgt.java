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

import org.apache.commons.lang.ArrayUtils;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;

/**
 * Builds exceptions and log messages from the {@link ErrorMessage} catalogue, so every failure the Daon
 * connector reports carries its {@code DAON-} error code.
 *
 * <p>The connector spans three exception families and this class bridges all of them from the one
 * catalogue:</p>
 * <ul>
 *   <li><b>Flow path</b> (registration, invited user, password recovery) — {@code FlowEngine*Exception}.
 *       These must be built here rather than through
 *       {@code OpenIDConnectExecutor.handleFlowEngineServerException}, which discards the caller's code and
 *       stamps the flow engine's own generic {@code 65013} instead.</li>
 *   <li><b>Login path</b> — {@link AuthenticationFailedException}. The framework drops the error code
 *       before it reaches the portal, so there the code is a diagnostic aid in the server log; the
 *       user-facing channel is the login retry page.</li>
 *   <li><b>Internal</b> — {@link DaonServerException}, raised by the utility classes and re-wrapped for
 *       whichever path called them (see {@link #toFlowServerException}). There is deliberately no client
 *       counterpart: every internal failure the connector raises is a server-side one, and the client
 *       errors it reports are all built directly as flow-engine or authentication-framework
 *       exceptions.</li>
 * </ul>
 *
 * <p>For failures that are deliberately swallowed (the connector degrades rather than failing the flow),
 * use {@link #errorLog(ErrorMessage, Object...)} to keep the code in the log line without changing
 * control flow.</p>
 */
public class DaonExceptionMgt {

    private DaonExceptionMgt() {
    }

    /**
     * Formats an error's description with the caller's arguments, leaving it untouched when there are
     * none, so an unfilled {@code %s} template never reaches a log or a client.
     */
    private static String describe(ErrorMessage error, Object... data) {

        if (ArrayUtils.isNotEmpty(data)) {
            return String.format(error.getDescription(), data);
        }
        return error.getDescription();
    }

    /**
     * Renders an error as a log line, e.g. {@code "DAON-65008 - Error resolving the referenced Daon IDP
     * for resource id: abc"}. For sites that log and continue rather than throwing.
     */
    public static String errorLog(ErrorMessage error, Object... data) {

        return error.getCode() + " - " + describe(error, data);
    }

    // Internal exceptions.

    public static DaonServerException handleServerException(ErrorMessage error, Object... data) {

        return new DaonServerException(error.getCode(), describe(error, data));
    }

    public static DaonServerException handleServerException(ErrorMessage error, Throwable cause,
                                                            Object... data) {

        return new DaonServerException(error.getCode(), describe(error, data), cause);
    }

    // Flow execution engine exceptions.

    /**
     * Builds a client exception carrying the {@code {{ }}} i18n tokens the flow portal renders, so the
     * wording the end user sees is resolved and localized by the portal rather than shipped from here.
     * An error with no i18n key falls back to its catalogue message, which the portal leaves unrendered in
     * favour of its own flow-type wording.
     *
     * <p>The diagnostic description is deliberately not sent — it can name internal configuration. Log it
     * at the call site with {@link #errorLog(ErrorMessage, Object...)} where the detail is needed.</p>
     */
    public static FlowEngineClientException handleFlowClientException(ErrorMessage error) {

        return new FlowEngineClientException(error.getCode(), userMessage(error), userDescription(error));
    }

    /**
     * The heading the flow portal should render for an error, as the token that marks it user-facing.
     */
    public static String userMessage(ErrorMessage error) {

        return error.getUserMessageToken() != null ? error.getUserMessageToken() : error.getMessage();
    }

    /**
     * The body the flow portal should render for an error, as the token that marks it user-facing.
     */
    public static String userDescription(ErrorMessage error) {

        return error.getUserDescriptionToken() != null
                ? error.getUserDescriptionToken() : error.getMessage();
    }

    public static FlowEngineServerException handleFlowServerException(ErrorMessage error, Object... data) {

        return new FlowEngineServerException(error.getCode(), error.getMessage(), describe(error, data));
    }

    /**
     * Re-wraps an internal Daon exception as a flow engine exception, preserving the original error code
     * and message so the code raised at the point of failure is the one the flow reports.
     */
    public static FlowEngineServerException toFlowServerException(DaonException e) {

        return new FlowEngineServerException(e.getErrorCode(), e.getMessage(), e.getMessage(), e);
    }

    // Authentication framework exceptions.

    /**
     * Builds an {@link AuthenticationFailedException} carrying the error code and the user-facing message.
     */
    public static AuthenticationFailedException handleAuthFailedException(ErrorMessage error) {

        return new AuthenticationFailedException(error.getCode(), error.getMessage());
    }

    public static AuthenticationFailedException handleAuthFailedException(ErrorMessage error,
                                                                          Throwable cause) {

        return new AuthenticationFailedException(error.getCode(), error.getMessage(), cause);
    }
}
