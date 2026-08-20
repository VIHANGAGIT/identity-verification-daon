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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.exception.FederatedAssociationManagerClientException;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.exception.FederatedAssociationManagerException;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.model.FederatedAssociation;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.internal.DaonConnectorDataHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;

/**
 * Helpers for storing the Daon verification state as a WSO2 federated identity association
 * (local user &lt;-&gt; Daon subject) in the built-in association store — no custom user claims.
 *
 * <p>The presence of an association with the Daon IDP means the user is Daon-verified; the
 * association's federated user id holds the Daon {@code preferred_username} used as {@code login_hint}.</p>
 */
public final class DaonFederatedAssociationUtil {

    private static final Log LOG = LogFactory.getLog(DaonFederatedAssociationUtil.class);

    private DaonFederatedAssociationUtil() {
    }

    /**
     * Builds an application-common {@link User} from a (possibly domain-qualified) username and tenant.
     *
     * <p>The association is stored against the (username, userstore domain, tenant) triple verbatim — both
     * {@code FederatedAssociationManagerImpl.createFederatedAssociation} and
     * {@code getFederatedAssociationsOfUser} pass {@code getUserStoreDomain()} and {@code getUserName()}
     * straight to the DAO — so the domain is part of the key and every caller has to arrive at the same
     * one. An <b>unqualified</b> username does not: {@link UserCoreUtil#extractDomainFromName} answers
     * with the bootstrap/primary domain for a name that carries none, whatever userstore the user is
     * really in. Callers holding a bare username must resolve the domain first — see
     * {@link #resolveQualifiedUsername(FlowUser, String)} for the flow path.</p>
     */
    public static User buildUser(String username, String tenantDomain) {

        User user = new User();
        user.setUserName(UserCoreUtil.removeDomainFromName(username));
        user.setUserStoreDomain(UserCoreUtil.extractDomainFromName(username));
        user.setTenantDomain(tenantDomain);
        return user;
    }

    /**
     * The flow user's <b>domain-qualified</b> username, for building the {@link User} a flow's Daon
     * association is keyed on.
     *
     * <p>{@code FlowUser.getUsername()} is whatever the flow collected — the username claim, or an email
     * address — and is not domain-qualified by the flow engine. Handing it to
     * {@link #buildUser(String, String)} as-is keys the association on the primary domain regardless of
     * the userstore the user actually lives in, while the login step keys on the real domain (it rebuilds
     * the name from {@code AuthenticatedUser.getUserStoreDomain()}). For a user outside the primary
     * userstore the two never meet:</p>
     * <ul>
     *   <li>on the enrolment flows the write fails, because the association store checks the user exists
     *       under the domain it was given — so a registration that has already verified with Daon and
     *       provisioned the user ends on {@code DAON-65013};</li>
     *   <li>on password recovery the read fails the same way and is caught as "no association", so an
     *       enrolled user is turned away with {@code DAON-60001}.</li>
     * </ul>
     *
     * <p>The domain is taken from the flow user when it carries one, and otherwise resolved from the
     * userstore by user id. Falling back to the bare username keeps the previous behaviour for the
     * primary-userstore case, where the two agree anyway.</p>
     *
     * @param flowUser     the flow user; may be {@code null}.
     * @param tenantDomain tenant the user lives in.
     * @return the qualified username, or {@code null} when the flow user carries no username at all.
     */
    public static String resolveQualifiedUsername(FlowUser flowUser, String tenantDomain) {

        if (flowUser == null) {
            return null;
        }
        String username = flowUser.getUsername();
        if (StringUtils.isBlank(username)) {
            return null;
        }
        if (username.contains(UserCoreConstants.DOMAIN_SEPARATOR)) {
            return username;
        }
        if (StringUtils.isNotBlank(flowUser.getUserStoreDomain())) {
            return flowUser.getUserStoreDomain() + UserCoreConstants.DOMAIN_SEPARATOR + username;
        }
        String resolved = resolveDomainQualifiedUsername(flowUser.getUserId(), tenantDomain);
        return resolved != null ? resolved : username;
    }

    /**
     * Asks the userstore for the domain-qualified name of the user with the given id.
     *
     * <p>{@code getDomainQualifiedUsername()} is used rather than
     * {@code AbstractUserStoreManager.getUserNameFromUserID}, which is only qualified on one of its two
     * branches.</p>
     *
     * @return the qualified username, or {@code null} when it cannot be resolved — the caller then keeps
     *         the unqualified name, which is what it would have used anyway.
     */
    private static String resolveDomainQualifiedUsername(String userId, String tenantDomain) {

        if (StringUtils.isBlank(userId) || StringUtils.isBlank(tenantDomain)
                || DaonConnectorDataHolder.getRealmService() == null) {
            return null;
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            UserStoreManager userStoreManager = DaonConnectorDataHolder.getRealmService()
                    .getTenantUserRealm(tenantId).getUserStoreManager();
            if (!(userStoreManager instanceof UniqueIDUserStoreManager)) {
                return null;
            }
            org.wso2.carbon.user.core.common.User storeUser =
                    ((UniqueIDUserStoreManager) userStoreManager).getUserWithID(userId, null, null);
            if (storeUser != null && StringUtils.isNotBlank(storeUser.getDomainQualifiedUsername())) {
                return storeUser.getDomainQualifiedUsername();
            }
        } catch (UserStoreException e) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_RESOLVING_USER_STORE_DOMAIN), e);
        }
        return null;
    }

    /**
     * Returns the Daon subject ({@code preferred_username}) from the user's association with the given
     * Daon IDP.
     *
     * <p><b>Null and empty mean different things and callers must not conflate them:</b></p>
     * <ul>
     *   <li>{@code null} — no association with that IDP could be found (not enrolled), or the lookup could
     *       not be performed at all. Nothing proves the user is enrolled.</li>
     *   <li>the <b>empty string</b> — an association exists but carries no federated user id. The user
     *       <em>is</em> enrolled, but there is no usable {@code login_hint} to re-verify against.</li>
     *   <li>a non-blank value — enrolled, and this is the Daon subject to hint at and bind the response
     *       to.</li>
     * </ul>
     *
     * <p>So "is this user enrolled?" is a {@code != null} test, and "do I have a usable subject?" is a
     * not-blank test. Testing not-blank for the former would let an account with an empty association past
     * an already-enrolled guard and enrol a second identity for it.</p>
     */
    public static String getAssociatedDaonSubject(User user, String idpName) {

        if (user == null || StringUtils.isBlank(idpName)) {
            LOG.debug("Null user or blank IDP name; cannot resolve the Daon verification state.");
            return null;
        }
        FederatedAssociationManager manager = DaonConnectorDataHolder.getFederatedAssociationManager();
        if (manager == null) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_FED_ASSOCIATION_MANAGER_UNAVAILABLE,
                    "cannot resolve the Daon verification state"));
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
        } catch (FederatedAssociationManagerClientException e) {
            // Expected, the user identifier does not resolve to an existing user. Password recovery routes even a
            // non-existent user through the first step (to avoid user enumeration).
            if (LOG.isDebugEnabled()) {
                LOG.debug("Could not resolve Daon federated associations for the user (the user likely does "
                        + "not exist); treating as not verified. IDP: " + idpName, e);
            }
        } catch (FederatedAssociationManagerException e) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_RESOLVING_FED_ASSOCIATION, idpName), e);
        }
        return null;
    }

    /**
     * Returns the username of the local user already associated with the given Daon subject on the given
     * Daon IDP, or {@code null} if no local user has claimed that Daon identity (or the lookup could not be
     * performed).
     *
     * <p>Used before an enrolment records an association, to keep one Daon identity from backing two
     * accounts. A {@code null} return does not by itself prove the identity is unclaimed — it also covers a
     * failed lookup — so a caller relying on exclusivity must still treat a subsequent association failure
     * (the store enforces uniqueness) as the authoritative answer.</p>
     */
    public static String getLocalUserForDaonSubject(String tenantDomain, String idpName, String daonSubject) {

        if (StringUtils.isBlank(tenantDomain) || StringUtils.isBlank(idpName)
                || StringUtils.isBlank(daonSubject)) {
            LOG.debug("Blank tenant domain, IDP name or Daon subject; cannot resolve the associated user.");
            return null;
        }
        FederatedAssociationManager manager = DaonConnectorDataHolder.getFederatedAssociationManager();
        if (manager == null) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_FED_ASSOCIATION_MANAGER_UNAVAILABLE,
                    "cannot resolve the local user holding the Daon identity"));
            return null;
        }
        try {
            return manager.getUserForFederatedAssociation(tenantDomain, idpName, daonSubject);
        } catch (FederatedAssociationManagerException e) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_RESOLVING_FED_ASSOCIATION, idpName), e);
            return null;
        }
    }

    /**
     * Creates a federated association between the local user and the Daon IDP.
     *
     * <p>Never throws: the failure — most commonly that the store rejected the write because the Daon
     * identity is already associated — is logged with its code and reported through the return value, so
     * the caller decides how to react. Both callers treat a failed write as fatal (the login step fails
     * the authentication, the registration listener fails the flow), so a caller that can legitimately
     * tolerate an existing association must rule that case out first — see
     * {@link #getAssociatedDaonSubject(User, String)}.</p>
     *
     * @return {@code true} if the association was created.
     */
    public static boolean createAssociation(User user, String idpName, String daonSubject) {

        if (user == null || StringUtils.isBlank(idpName) || StringUtils.isBlank(daonSubject)) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_PERSISTING_FED_ASSOCIATION,
                    "the user, the IDP name or the Daon subject is missing"));
            return false;
        }
        FederatedAssociationManager manager = DaonConnectorDataHolder.getFederatedAssociationManager();
        if (manager == null) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_FED_ASSOCIATION_MANAGER_UNAVAILABLE,
                    "the Daon verification state was not persisted"));
            return false;
        }
        try {
            manager.createFederatedAssociation(user, idpName, daonSubject);
            return true;
        } catch (FederatedAssociationManagerException e) {
            // Not ignorable: both callers treat a failed write as fatal, so this is logged with its code
            // and reported through the return value rather than swallowed. The store rejects a write when
            // the Daon subject is already associated on this IDP, or when the user does not exist under
            // the (username, userstore domain, tenant) it was given — so the caller has to have named the
            // user the same way the read side does.
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_CREATING_FED_ASSOCIATION, idpName), e);
            return false;
        }
    }
}
