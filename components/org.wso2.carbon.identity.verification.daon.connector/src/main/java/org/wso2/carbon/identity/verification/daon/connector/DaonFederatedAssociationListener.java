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

package org.wso2.carbon.identity.verification.daon.connector;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.listener.AbstractFlowExecutionListener;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionStep;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonFederatedAssociationUtil;

import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_FED_IDP_NAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_FED_SUBJECT;

/**
 * Persists the Daon federated association (local user &lt;-&gt; Daon subject) once a registration flow
 * completes and the user ID/username is guaranteed available. {@link DaonExecutor} stashes the IDP name
 * and Daon subject in the flow context; this listener writes the association via
 * {@link DaonFederatedAssociationUtil} for both self sign-up and invited-user registration.
 *
 * <p>The write is treated as part of the flow, not as best-effort bookkeeping: once the flow has verified
 * with Daon, a failure to record the enrolment fails the flow. This matches how the OIDC connector's
 * registration path behaves — {@code OpenIDConnectExecutor} stashes the association on the flow user and
 * {@code UserProvisioningExecutor} throws {@code ERROR_CODE_USER_ONBOARD_FAILURE} if the write fails —
 * and it keeps a completed registration from reporting success while leaving the account looking
 * not-enrolled at the next login.</p>
 *
 * <p>Note that, exactly as in the OIDC case, the association is written after the user has been
 * provisioned and the provisioning executor supports no rollback, so a failure here leaves the user
 * created without an enrolment. Failing is still the better outcome: the caller learns the registration
 * did not fully succeed instead of discovering it at the next login.</p>
 */
public class DaonFederatedAssociationListener extends AbstractFlowExecutionListener {

    private static final Log LOG = LogFactory.getLog(DaonFederatedAssociationListener.class);

    @Override
    public int getExecutionOrderId() {
        return 10;
    }

    @Override
    public int getDefaultOrderId() {
        return 10;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean doPostExecute(FlowExecutionStep step, FlowExecutionContext context) throws FlowEngineException {

        if (!Constants.STATUS_COMPLETE.equals(step.getFlowStatus())) {
            return true;
        }
        String daonSubject = (String) context.getProperty(DAON_FED_SUBJECT);
        String idpName = (String) context.getProperty(DAON_FED_IDP_NAME);
        // Neither property set means the flow never went through Daon, which is the normal case for any
        // other registration flow — nothing to persist and nothing to report. A flow that did verify with
        // Daon cannot land here: DaonExecutor fails the callback if it cannot resolve both values, rather
        // than leaving them unset and letting the flow complete unenrolled.
        if (StringUtils.isBlank(daonSubject) && StringUtils.isBlank(idpName)) {
            return true;
        }
        // Past this point the flow did verify with Daon, so any missing piece means the enrolment cannot be
        // recorded and the user would look "not enrolled" at their next login. Fail the flow rather than
        // complete it with the enrolment lost.
        if (StringUtils.isBlank(daonSubject) || StringUtils.isBlank(idpName)) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_PERSISTING_FED_ASSOCIATION,
                    "the Daon subject or the IDP name is missing from the flow context");
        }
        if (context.getFlowUser() == null) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_PERSISTING_FED_ASSOCIATION,
                    "the completed flow has no flow user");
        }
        String username = context.getFlowUser().getUsername();
        if (StringUtils.isBlank(username)) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_PERSISTING_FED_ASSOCIATION,
                    "the flow user has no username");
        }
        User user = DaonFederatedAssociationUtil.buildUser(username, context.getTenantDomain());
        // This user already holding exactly this Daon identity is the one benign reason the write below
        // would fail (the store rejects a duplicate). Nothing is lost, so let the flow complete.
        if (daonSubject.equals(DaonFederatedAssociationUtil.getAssociatedDaonSubject(user, idpName))) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("The Daon enrolment is already recorded for the flow user on IDP: " + idpName);
            }
            return true;
        }
        // Any other user holding it means this registration verified an identity that already backs a
        // different account, which is the case the login path fails on too: one Daon identity must not
        // satisfy identity proofing for two accounts.
        String claimedBy = DaonFederatedAssociationUtil.getLocalUserForDaonSubject(context.getTenantDomain(),
                idpName, daonSubject);
        if (StringUtils.isNotBlank(claimedBy)) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_DAON_IDENTITY_ALREADY_ENROLLED, idpName));
            throw DaonExceptionMgt.handleFlowClientException(ErrorMessage.ERROR_DAON_IDENTITY_ALREADY_ENROLLED);
        }
        if (!DaonFederatedAssociationUtil.createAssociation(user, idpName, daonSubject)) {
            // The util has already logged the specific cause with its own code. The store enforces
            // uniqueness on (IDP, Daon subject), so this also catches an identity claimed by another
            // account between the lookup above and this write.
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_CREATING_FED_ASSOCIATION, idpName);
        }
        return true;
    }
}
