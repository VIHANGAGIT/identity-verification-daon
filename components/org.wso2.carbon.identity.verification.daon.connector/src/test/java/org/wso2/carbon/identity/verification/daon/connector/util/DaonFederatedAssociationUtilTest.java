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

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.verification.daon.connector.internal.DaonConnectorDataHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

/**
 * Tests how the flow path names the local user its Daon association is keyed on.
 *
 * <p>The association is stored against (username, userstore domain, tenant) verbatim, and the login step
 * keys on the user's real userstore domain. So the flow path has to arrive at the same domain — an
 * unqualified flow-user name resolves to the primary userstore whatever store the user is really in, and
 * the enrolment and the later lookup then never meet.</p>
 */
public class DaonFederatedAssociationUtilTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final int TENANT_ID = 1;
    private static final String SECONDARY = "SECONDARY";
    private static final String USER_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    @AfterMethod
    public void tearDown() {

        DaonConnectorDataHolder.setRealmService(null);
    }

    private FlowUser flowUser(String username, String userStoreDomain, String userId) {

        FlowUser flowUser = new FlowUser();
        if (username != null) {
            flowUser.setUsername(username);
        }
        flowUser.setUserStoreDomain(userStoreDomain);
        flowUser.setUserId(userId);
        return flowUser;
    }

    /**
     * Wires a realm whose userstore manager resolves {@link #USER_ID} to the given qualified name.
     */
    private void givenUserStoreResolves(String domainQualifiedUsername) throws Exception {

        org.wso2.carbon.user.core.common.User storeUser = new org.wso2.carbon.user.core.common.User();
        storeUser.setUserID(USER_ID);
        storeUser.setUsername(domainQualifiedUsername);

        UniqueIDUserStoreManager userStoreManager = Mockito.mock(UniqueIDUserStoreManager.class);
        Mockito.when(userStoreManager.getUserWithID(USER_ID, null, null)).thenReturn(storeUser);
        UserRealm userRealm = Mockito.mock(UserRealm.class);
        Mockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        RealmService realmService = Mockito.mock(RealmService.class);
        Mockito.when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        DaonConnectorDataHolder.setRealmService(realmService);
    }

    @Test
    public void testAlreadyQualifiedUsernameIsKeptAsIs() {

        // No userstore lookup should be needed, so no realm service is wired.
        assertEquals(DaonFederatedAssociationUtil.resolveQualifiedUsername(
                flowUser(SECONDARY + "/john", null, USER_ID), TENANT_DOMAIN), SECONDARY + "/john");
    }

    /**
     * The regression this guards: the flow user's own userstore domain has to reach the association, or
     * the enrolment is keyed on the primary userstore and the login step never finds it.
     */
    @Test
    public void testFlowUserUserStoreDomainQualifiesTheUsername() {

        String qualified = DaonFederatedAssociationUtil.resolveQualifiedUsername(
                flowUser("john", SECONDARY, USER_ID), TENANT_DOMAIN);

        assertEquals(qualified, SECONDARY + "/john");

        // And the User the association is actually stored against carries that domain.
        User user = DaonFederatedAssociationUtil.buildUser(qualified, TENANT_DOMAIN);
        assertEquals(user.getUserStoreDomain(), SECONDARY);
        assertEquals(user.getUserName(), "john");
        assertEquals(user.getTenantDomain(), TENANT_DOMAIN);
    }

    @Test
    public void testDomainResolvedFromUserStoreByUserIdWhenFlowUserCarriesNone() throws Exception {

        givenUserStoreResolves(SECONDARY + "/john");
        try (MockedStatic<IdentityTenantUtil> tenantUtil = Mockito.mockStatic(IdentityTenantUtil.class)) {
            tenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);

            String qualified = DaonFederatedAssociationUtil.resolveQualifiedUsername(
                    flowUser("john", null, USER_ID), TENANT_DOMAIN);

            assertEquals(qualified, SECONDARY + "/john");
            assertEquals(DaonFederatedAssociationUtil.buildUser(qualified, TENANT_DOMAIN)
                    .getUserStoreDomain(), SECONDARY);
        }
    }

    /**
     * With no domain anywhere the bare username is kept, which is the behaviour that predates the fix:
     * for a primary-userstore user the two sides agree on it anyway.
     */
    @Test
    public void testFallsBackToTheBareUsernameWhenTheDomainCannotBeResolved() {

        String qualified = DaonFederatedAssociationUtil.resolveQualifiedUsername(
                flowUser("john", null, null), TENANT_DOMAIN);

        assertEquals(qualified, "john");
        assertEquals(DaonFederatedAssociationUtil.buildUser(qualified, TENANT_DOMAIN).getUserStoreDomain(),
                UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
    }

    /**
     * A userstore failure must not fail the flow — the caller keeps the unqualified name, which is what it
     * would have used before.
     */
    @Test
    public void testUserStoreFailureFallsBackToTheBareUsername() throws Exception {

        UniqueIDUserStoreManager userStoreManager = Mockito.mock(UniqueIDUserStoreManager.class);
        Mockito.when(userStoreManager.getUserWithID(USER_ID, null, null))
                .thenThrow(new org.wso2.carbon.user.core.UserStoreException("boom"));
        UserRealm userRealm = Mockito.mock(UserRealm.class);
        Mockito.when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        RealmService realmService = Mockito.mock(RealmService.class);
        Mockito.when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        DaonConnectorDataHolder.setRealmService(realmService);

        try (MockedStatic<IdentityTenantUtil> tenantUtil = Mockito.mockStatic(IdentityTenantUtil.class)) {
            tenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);

            assertEquals(DaonFederatedAssociationUtil.resolveQualifiedUsername(
                    flowUser("john", null, USER_ID), TENANT_DOMAIN), "john");
        }
    }

    /**
     * A flow user carrying no username at all resolves to nothing, so the callers report it rather than
     * keying an association on a blank name.
     *
     * <p>{@link FlowUser} is mocked here rather than built: {@code getUsername()} is not a plain getter —
     * with nothing set it derives a username through {@code FlowExecutionEngineUtils}, which reaches for
     * the input-validation service and is not resolvable off-container.</p>
     */
    @Test
    public void testNoFlowUserOrNoUsernameResolvesToNothing() {

        assertNull(DaonFederatedAssociationUtil.resolveQualifiedUsername(null, TENANT_DOMAIN));

        FlowUser noUsername = Mockito.mock(FlowUser.class);
        Mockito.when(noUsername.getUsername()).thenReturn(null);
        assertNull(DaonFederatedAssociationUtil.resolveQualifiedUsername(noUsername, TENANT_DOMAIN));

        FlowUser blankUsername = Mockito.mock(FlowUser.class);
        Mockito.when(blankUsername.getUsername()).thenReturn("   ");
        assertNull(DaonFederatedAssociationUtil.resolveQualifiedUsername(blankUsername, TENANT_DOMAIN));
    }

    /**
     * The login path builds its User from an already-qualified name, so {@code buildUser} must keep
     * splitting one — this is the side the flow path now has to agree with.
     */
    @Test
    public void testBuildUserSplitsAQualifiedName() {

        User user = DaonFederatedAssociationUtil.buildUser(SECONDARY + "/john", TENANT_DOMAIN);

        assertEquals(user.getUserName(), "john");
        assertEquals(user.getUserStoreDomain(), SECONDARY);
    }
}
