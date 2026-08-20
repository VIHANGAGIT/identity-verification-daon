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

import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.internal.DaonConnectorDataHolder;
import org.wso2.carbon.idp.mgt.IdpManager;

import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Tests the dereferencing of {@code daon_idp_id}.
 *
 * <p>The subject of most of these is the guard that a reference is only honoured when it names a Daon
 * connection. The reference decides which OIDC client credentials and endpoints a Daon request is built
 * from, so a reference that resolved to any connection in the tenant would let one be configured to run
 * what the flows treat as a Daon identity verification against an unrelated provider.</p>
 */
public class DaonReferencedIdpUtilTest {

    private static final String IDP_RESOURCE_ID = "11111111-2222-3333-4444-555555555555";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String DAON_IDP_NAME = "Daon TrustX Identity Verifier";

    @AfterMethod
    public void tearDown() {

        DaonConnectorDataHolder.setIdpManager(null);
    }

    private Property property(String name, String value) {

        Property property = new Property();
        property.setName(name);
        property.setValue(value);
        return property;
    }

    private FederatedAuthenticatorConfig authenticatorConfig(String name, Property... properties) {

        FederatedAuthenticatorConfig config = new FederatedAuthenticatorConfig();
        config.setName(name);
        config.setProperties(properties);
        return config;
    }

    /**
     * Registers an IdP under {@link #IDP_RESOURCE_ID}, as the referenced connection a login connection
     * would resolve.
     */
    private void givenReferencedIdp(IdentityProvider idp) throws Exception {

        IdpManager idpManager = Mockito.mock(IdpManager.class);
        Mockito.when(idpManager.getIdPByResourceId(IDP_RESOURCE_ID, TENANT_DOMAIN, false)).thenReturn(idp);
        DaonConnectorDataHolder.setIdpManager(idpManager);
    }

    private IdentityProvider daonIdp() {

        FederatedAuthenticatorConfig daonConfig = authenticatorConfig(DaonConstants.AUTHENTICATOR_NAME,
                property("ClientId", "daon-client"),
                property("ClientSecret", "daon-secret"),
                property("OAuth2AuthzEPUrl", "https://daon.example.com/authorize"),
                property("OAuth2TokenEPUrl", "https://daon.example.com/token"));

        IdentityProvider idp = new IdentityProvider();
        idp.setIdentityProviderName(DAON_IDP_NAME);
        idp.setDefaultAuthenticatorConfig(daonConfig);
        idp.setFederatedAuthenticatorConfigs(new FederatedAuthenticatorConfig[]{daonConfig});
        return idp;
    }

    private Map<String, String> referencingProps() {

        Map<String, String> props = new HashMap<>();
        props.put(DaonConstants.DAON_IDP_ID, IDP_RESOURCE_ID);
        props.put(DaonConstants.DAON_LOGIN_PD, "LoginProcess:1");
        return props;
    }

    @Test
    public void testReferencedDaonConnectionSuppliesTheOidcConfig() throws Exception {

        givenReferencedIdp(daonIdp());

        Map<String, String> effective =
                DaonReferencedIdpUtil.buildEffectiveProperties(referencingProps(), TENANT_DOMAIN);

        assertEquals(effective.get("ClientId"), "daon-client");
        assertEquals(effective.get("OAuth2TokenEPUrl"), "https://daon.example.com/token");
        // The login process definition belongs to the login connection and must survive the layering.
        assertEquals(effective.get(DaonConstants.DAON_LOGIN_PD), "LoginProcess:1");
        assertEquals(DaonReferencedIdpUtil.resolveIdpName(IDP_RESOURCE_ID, TENANT_DOMAIN), DAON_IDP_NAME);
    }

    /**
     * The guard. A reference naming a connection of any other authenticator type must yield nothing at
     * all: no client credentials, no endpoints, no IDP name to key an enrolment on, no claim mappings.
     */
    @Test
    public void testReferenceToANonDaonConnectionIsRefused() throws Exception {

        IdentityProvider googleIdp = new IdentityProvider();
        googleIdp.setIdentityProviderName("Google");
        FederatedAuthenticatorConfig googleConfig = authenticatorConfig("GoogleOIDCAuthenticator",
                property("ClientId", "someone-elses-client"),
                property("ClientSecret", "someone-elses-secret"),
                property("OAuth2AuthzEPUrl", "https://accounts.google.com/o/oauth2/auth"),
                property("OAuth2TokenEPUrl", "https://oauth2.googleapis.com/token"));
        googleIdp.setDefaultAuthenticatorConfig(googleConfig);
        googleIdp.setFederatedAuthenticatorConfigs(new FederatedAuthenticatorConfig[]{googleConfig});
        ClaimConfig claimConfig = new ClaimConfig();
        claimConfig.setClaimMappings(new ClaimMapping[]{
                ClaimMapping.build("http://wso2.org/claims/givenname", "given_name", null, true)});
        googleIdp.setClaimConfig(claimConfig);

        givenReferencedIdp(googleIdp);

        Map<String, String> effective =
                DaonReferencedIdpUtil.buildEffectiveProperties(referencingProps(), TENANT_DOMAIN);

        assertNull(effective.get("ClientId"), "The other connection's client id must not be borrowed.");
        assertNull(effective.get("ClientSecret"),
                "The other connection's client secret must not be borrowed.");
        assertNull(effective.get("OAuth2AuthzEPUrl"),
                "A Daon request must not be built against another provider's authorize endpoint.");
        assertNull(effective.get("OAuth2TokenEPUrl"));
        // Nothing to key a federated association on, so no enrolment can be recorded either.
        assertNull(DaonReferencedIdpUtil.resolveIdpName(IDP_RESOURCE_ID, TENANT_DOMAIN));
        assertTrue(DaonReferencedIdpUtil.resolveClaimMappings(IDP_RESOURCE_ID, TENANT_DOMAIN).isEmpty());
    }

    /**
     * The connection's own properties are still carried through, so the refusal shows up as the missing
     * OIDC configuration the callers already report (DAON-65001) rather than as an empty map.
     */
    @Test
    public void testRefusedReferenceKeepsTheConnectionsOwnProperties() throws Exception {

        IdentityProvider notDaon = new IdentityProvider();
        notDaon.setIdentityProviderName("Some SAML IdP");
        notDaon.setFederatedAuthenticatorConfigs(new FederatedAuthenticatorConfig[]{
                authenticatorConfig("SAMLSSOAuthenticator", property("ClientId", "irrelevant"))});
        givenReferencedIdp(notDaon);

        Map<String, String> effective =
                DaonReferencedIdpUtil.buildEffectiveProperties(referencingProps(), TENANT_DOMAIN);

        assertEquals(effective.get(DaonConstants.DAON_IDP_ID), IDP_RESOURCE_ID);
        assertEquals(effective.get(DaonConstants.DAON_LOGIN_PD), "LoginProcess:1");
        assertFalse(effective.containsKey("ClientId"));
    }

    /**
     * The Daon configuration is selected by name rather than by taking the first one, so a connection
     * carrying more than one federated authenticator still yields the Daon client configuration.
     */
    @Test
    public void testDaonConfigIsSelectedByNameNotByPosition() throws Exception {

        FederatedAuthenticatorConfig otherConfig = authenticatorConfig("OpenIDConnectAuthenticator",
                property("ClientId", "stock-oidc-client"));
        FederatedAuthenticatorConfig daonConfig = authenticatorConfig(DaonConstants.AUTHENTICATOR_NAME,
                property("ClientId", "daon-client"),
                property(DaonConstants.DAON_ENROL_PD, "EnrolProcess:2"));

        IdentityProvider idp = new IdentityProvider();
        idp.setIdentityProviderName(DAON_IDP_NAME);
        // No default set, and the non-Daon configuration comes first.
        idp.setFederatedAuthenticatorConfigs(
                new FederatedAuthenticatorConfig[]{otherConfig, daonConfig});
        givenReferencedIdp(idp);

        Map<String, String> effective =
                DaonReferencedIdpUtil.buildEffectiveProperties(referencingProps(), TENANT_DOMAIN);

        assertEquals(effective.get("ClientId"), "daon-client");
        assertEquals(effective.get(DaonConstants.DAON_ENROL_PD), "EnrolProcess:2");
    }

    /**
     * A self-contained Identity Verifier connection carries no reference, so nothing is dereferenced and
     * its own properties are used as they are.
     */
    @Test
    public void testSelfContainedConnectionIsNotDereferenced() throws Exception {

        IdpManager idpManager = Mockito.mock(IdpManager.class);
        DaonConnectorDataHolder.setIdpManager(idpManager);

        Map<String, String> ownProps = new HashMap<>();
        ownProps.put("ClientId", "own-client");
        ownProps.put(DaonConstants.DAON_ENROL_PD, "EnrolProcess:1");

        Map<String, String> effective =
                DaonReferencedIdpUtil.buildEffectiveProperties(ownProps, TENANT_DOMAIN);

        assertEquals(effective.get("ClientId"), "own-client");
        assertEquals(effective.get(DaonConstants.DAON_ENROL_PD), "EnrolProcess:1");
        Mockito.verifyNoInteractions(idpManager);
    }

    @Test
    public void testMissingReferencedConnectionResolvesToNothing() throws Exception {

        givenReferencedIdp(null);

        assertNull(DaonReferencedIdpUtil.resolveIdpName(IDP_RESOURCE_ID, TENANT_DOMAIN));
        assertFalse(DaonReferencedIdpUtil
                .buildEffectiveProperties(referencingProps(), TENANT_DOMAIN).containsKey("ClientId"));
    }

    /**
     * With no IdP management service there is no way to tell a Daon reference from any other, so the
     * reference must resolve to nothing rather than be assumed valid.
     */
    @Test
    public void testUnavailableIdpManagerResolvesToNothing() {

        DaonConnectorDataHolder.setIdpManager(null);

        assertNull(DaonReferencedIdpUtil.resolveIdpName(IDP_RESOURCE_ID, TENANT_DOMAIN));
        assertTrue(DaonReferencedIdpUtil.resolveClaimMappings(IDP_RESOURCE_ID, TENANT_DOMAIN).isEmpty());
        assertFalse(DaonReferencedIdpUtil
                .buildEffectiveProperties(referencingProps(), TENANT_DOMAIN).containsKey("ClientId"));
    }

    @Test
    public void testClaimMappingsComeFromAReferencedDaonConnection() throws Exception {

        IdentityProvider idp = daonIdp();
        ClaimConfig claimConfig = new ClaimConfig();
        claimConfig.setClaimMappings(new ClaimMapping[]{
                ClaimMapping.build("http://wso2.org/claims/givenname", "given_name", null, true),
                ClaimMapping.build("http://wso2.org/claims/dob", "birthdate", null, true),
                // Incomplete mappings are skipped rather than stored half-resolved.
                ClaimMapping.build("http://wso2.org/claims/lastname", "", null, true)});
        idp.setClaimConfig(claimConfig);
        givenReferencedIdp(idp);

        Map<String, String> mappings =
                DaonReferencedIdpUtil.resolveClaimMappings(IDP_RESOURCE_ID, TENANT_DOMAIN);

        assertEquals(mappings.size(), 2);
        assertEquals(mappings.get("http://wso2.org/claims/givenname"), "given_name");
        assertEquals(mappings.get("http://wso2.org/claims/dob"), "birthdate");
    }
}
