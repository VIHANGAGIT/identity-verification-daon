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

package org.wso2.carbon.identity.verification.daon.connector.internal;

import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Service holder for the Daon TrustX connector OSGi bundle.
 */
public final class DaonConnectorDataHolder {

    private static RealmService realmService;
    private static OrganizationManager organizationManager;
    private static FederatedAssociationManager federatedAssociationManager;
    private static IdpManager idpManager;

    private DaonConnectorDataHolder() {
    }

    public static RealmService getRealmService() {

        return realmService;
    }

    public static void setRealmService(RealmService realmService) {

        DaonConnectorDataHolder.realmService = realmService;
    }

    public static OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    public static void setOrganizationManager(OrganizationManager organizationManager) {

        DaonConnectorDataHolder.organizationManager = organizationManager;
    }

    public static FederatedAssociationManager getFederatedAssociationManager() {

        return federatedAssociationManager;
    }

    public static void setFederatedAssociationManager(FederatedAssociationManager federatedAssociationManager) {

        DaonConnectorDataHolder.federatedAssociationManager = federatedAssociationManager;
    }

    public static IdpManager getIdpManager() {

        return idpManager;
    }

    public static void setIdpManager(IdpManager idpManager) {

        DaonConnectorDataHolder.idpManager = idpManager;
    }
}
