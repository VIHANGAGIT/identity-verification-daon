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

package org.wso2.carbon.identity.verification.daon.authenticator;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.exception.FederatedAssociationManagerException;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.model.FederatedAssociation;
import org.wso2.carbon.identity.verification.daon.authenticator.internal.DaonAuthenticatorDataHolder;
import org.wso2.carbon.user.core.util.UserCoreUtil;

/**
 * Helpers for storing the Daon verification state as a WSO2 federated identity association
 * (local user &lt;-&gt; Daon subject) in the built-in association store — no custom user claims.
 *
 * <p>The presence of an association with the Daon IDP means the user is Daon-verified; the
 * association's federated user id holds the Daon {@code preferred_username} used as {@code login_hint}.</p>
 */
final class DaonFederatedAssociationUtil {

    private static final Log LOG = LogFactory.getLog(DaonFederatedAssociationUtil.class);

    private DaonFederatedAssociationUtil() {
    }

    /**
     * Builds an application-common {@link User} from a (possibly domain-qualified) username and tenant.
     */
    static User buildUser(String username, String tenantDomain) {

        User user = new User();
        user.setUserName(UserCoreUtil.removeDomainFromName(username));
        user.setUserStoreDomain(UserCoreUtil.extractDomainFromName(username));
        user.setTenantDomain(tenantDomain);
        return user;
    }

    /**
     * Returns the Daon subject ({@code preferred_username}) from the user's association with the given
     * Daon IDP, or {@code null} if the user has no association with that IDP (i.e. not yet verified).
     * A non-null (possibly empty) return means the user is Daon-verified.
     */
    static String getAssociatedDaonSubject(User user, String idpName) {

        if (user == null || StringUtils.isBlank(idpName)) {
            return null;
        }
        FederatedAssociationManager manager = DaonAuthenticatorDataHolder.getFederatedAssociationManager();
        if (manager == null) {
            LOG.warn("FederatedAssociationManager unavailable; cannot resolve Daon verification state.");
            return null;
        }
        try {
            FederatedAssociation[] associations = manager.getFederatedAssociationsOfUser(user);
            if (associations == null) {
                return null;
            }
            for (FederatedAssociation association : associations) {
                if (association.getIdp() != null && idpName.equals(association.getIdp().getName())) {
                    String subject = association.getFederatedUserId();
                    return subject != null ? subject : StringUtils.EMPTY;
                }
            }
        } catch (FederatedAssociationManagerException e) {
            LOG.warn("Error resolving Daon federated association for the user; treating as not verified.", e);
        }
        return null;
    }

    /**
     * Creates a federated association between the local user and the Daon IDP. Idempotent from the
     * caller's perspective: an "already associated" outcome is logged and swallowed.
     */
    static void createAssociation(User user, String idpName, String daonSubject) {

        if (user == null || StringUtils.isBlank(idpName) || StringUtils.isBlank(daonSubject)) {
            return;
        }
        FederatedAssociationManager manager = DaonAuthenticatorDataHolder.getFederatedAssociationManager();
        if (manager == null) {
            LOG.warn("FederatedAssociationManager unavailable; Daon verification state not persisted.");
            return;
        }
        try {
            manager.createFederatedAssociation(user, idpName, daonSubject);
        } catch (FederatedAssociationManagerException e) {
            // Typically already associated (re-verification) — safe to ignore.
            LOG.warn("Could not create Daon federated association (may already exist) for IDP: " + idpName, e);
        }
    }
}
