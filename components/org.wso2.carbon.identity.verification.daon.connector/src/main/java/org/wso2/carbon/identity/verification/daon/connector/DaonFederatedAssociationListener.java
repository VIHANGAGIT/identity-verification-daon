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
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.listener.AbstractFlowExecutionListener;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionStep;

import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_FED_IDP_NAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_FED_SUBJECT;

/**
 * Persists the Daon federated association (local user &lt;-&gt; Daon subject) once a registration flow
 * completes and the user ID/username is guaranteed available. {@link DaonExecutor} stashes the IDP name
 * and Daon subject in the flow context; this listener writes the association via
 * {@link DaonFederatedAssociationUtil} for both self sign-up and invited-user registration.
 */
public class DaonFederatedAssociationListener extends AbstractFlowExecutionListener {

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
    public boolean doPostExecute(FlowExecutionStep step, FlowExecutionContext context) {

        if (!Constants.STATUS_COMPLETE.equals(step.getFlowStatus())) {
            return true;
        }
        String daonSubject = (String) context.getProperty(DAON_FED_SUBJECT);
        String idpName = (String) context.getProperty(DAON_FED_IDP_NAME);
        if (StringUtils.isBlank(daonSubject) || StringUtils.isBlank(idpName) || context.getFlowUser() == null) {
            return true;
        }
        String username = context.getFlowUser().getUsername();
        if (StringUtils.isBlank(username)) {
            return true;
        }
        User user = DaonFederatedAssociationUtil.buildUser(username, context.getTenantDomain());
        DaonFederatedAssociationUtil.createAssociation(user, idpName, daonSubject);
        return true;
    }
}
