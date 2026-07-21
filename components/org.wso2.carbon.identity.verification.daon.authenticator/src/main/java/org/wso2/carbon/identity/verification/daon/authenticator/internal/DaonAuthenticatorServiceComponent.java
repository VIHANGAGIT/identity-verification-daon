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

package org.wso2.carbon.identity.verification.daon.authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.listener.FlowExecutionListener;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.identity.verification.daon.authenticator.DaonAuthenticator;
import org.wso2.carbon.identity.verification.daon.authenticator.DaonExecutor;
import org.wso2.carbon.identity.verification.daon.authenticator.DaonFederatedAssociationListener;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi service component for the Daon TrustX federated identity provider (authenticator + executor).
 */
@Component(
        name = "daon.identity.authenticator",
        immediate = true)
public class DaonAuthenticatorServiceComponent {

    private static final Log LOG = LogFactory.getLog(DaonAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            ctxt.getBundleContext().registerService(
                    ApplicationAuthenticator.class.getName(), new DaonAuthenticator(), null);
            ctxt.getBundleContext().registerService(
                    Executor.class.getName(), new DaonExecutor(), null);
            ctxt.getBundleContext().registerService(
                    FlowExecutionListener.class.getName(), new DaonFederatedAssociationListener(), null);
            if (LOG.isDebugEnabled()) {
                LOG.debug("DaonAuthenticator bundle activated successfully.");
            }
        } catch (Throwable e) {
            LOG.fatal("Error while activating DaonAuthenticator bundle", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("DaonAuthenticator bundle is deactivated.");
        }
    }

    @Reference(
            name = "RealmService",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        DaonAuthenticatorDataHolder.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        DaonAuthenticatorDataHolder.setRealmService(null);
    }

    @Reference(
            name = "FederatedAssociationManager",
            service = FederatedAssociationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetFederatedAssociationManager")
    protected void setFederatedAssociationManager(FederatedAssociationManager federatedAssociationManager) {

        DaonAuthenticatorDataHolder.setFederatedAssociationManager(federatedAssociationManager);
    }

    protected void unsetFederatedAssociationManager(FederatedAssociationManager federatedAssociationManager) {

        DaonAuthenticatorDataHolder.setFederatedAssociationManager(null);
    }

    @Reference(
            name = "OrganizationManager",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager")
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        DaonAuthenticatorDataHolder.setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        DaonAuthenticatorDataHolder.setOrganizationManager(null);
    }

    @Reference(
            name = "IdentityProviderManager",
            service = IdpManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdpManager")
    protected void setIdpManager(IdpManager idpManager) {

        DaonAuthenticatorDataHolder.setIdpManager(idpManager);
    }

    protected void unsetIdpManager(IdpManager idpManager) {

        DaonAuthenticatorDataHolder.setIdpManager(null);
    }
}
