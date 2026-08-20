/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.verification.daon.connector.constants;

/**
 * Constants used across the Daon TrustX connector — the API client, the login authenticator and the
 * flow executor.
 *
 * <p>Error codes and messages live in {@link DaonErrorConstants}.</p>
 */
public class DaonConstants {

    private DaonConstants() {
    }

    /*
     * Daon-specific parameters.
     */

    /**
     * OIDC login_hint query parameter used to pre-identify the user on the Daon authorization endpoint.
     */
    public static final String LOGIN_HINT = "login_hint";

    /**
     * OIDC request parameter carrying the selected Daon process definition.
     */
    public static final String ACR_VALUES_PARAM = "acr_values";

    /**
     * Standard OAuth2/OIDC error parameter returned on the callback.
     */
    public static final String OAUTH2_ERROR_DESCRIPTION = "error_description";

    /**
     * OIDC claims request parameter and verified_claims response keys.
     */
    public static final String CLAIMS_PARAM = "claims";
    /**
     * OIDC individual-claim-request member used to request that a claim be returned with (verified
     * against) a specific value.
     */
    public static final String CLAIM_VALUE_MEMBER = "value";
    public static final String VERIFIED_CLAIMS = "verified_claims";
    public static final String VERIFICATION = "verification";
    public static final String TRUST_FRAMEWORK = "trust_framework";
    public static final String TRUST_FRAMEWORK_VALUE = "daon-identify-1";
    public static final String ID_TOKEN_CONTAINER = "id_token";

    /**
     * Daon verified claim names requested in the OIDC {@code claims} parameter.
     */
    public static final String CLAIM_GIVEN_NAME = "given_name";
    public static final String CLAIM_FAMILY_NAME = "family_name";
    public static final String CLAIM_FAMILY_NAME_AND_GIVEN_NAME = "family_name_and_given_name";
    public static final String CLAIM_BIRTHDATE = "birthdate";
    public static final String CLAIM_DOCUMENT_TYPE = "document_type";
    public static final String CLAIM_DOCUMENT_CLASSIFICATION = "document_classification";
    public static final String CLAIM_DOCUMENT_DATE_OF_EXPIRY = "document_date_of_expiry";
    public static final String CLAIM_DOCUMENT_NUMBER = "document_number";
    public static final String CLAIM_DOCUMENT_PERSONAL_NUMBER = "document_personal_number";

    /**
     * Daon claim keys inside the "claims" JWT object, and the separator Daon uses inside its
     * multi-value fields.
     */
    public static final String CLAIM_ADDRESS = "address";
    public static final String CLAIM_ADDRESS_FORMATTED = "formatted";
    public static final String DAON_FIELD_SEPARATOR = "^";

    /**
     * Top-level JWT claim field names in the Daon ID token.
     */
    public static final String JWT_SUBJECT_CLAIM = "sub";
    public static final String JWT_VERIFIED_CLAIMS_OBJECT = "verifiedClaims";
    public static final String JWT_CLAIMS_OBJECT = "claims";

    /**
     * Daon preferred_username claim — the Daon-assigned identifier returned in the ID token.
     * Stored in the federated association after successful verification and used as login_hint during
     * face auth.
     */
    public static final String JWT_PREFERRED_USERNAME_CLAIM = "preferred_username";

    /**
     * Name of the federated authenticator handling the Daon login (re-verification) step, and the
     * friendly name shown for it.
     */
    public static final String AUTHENTICATOR_NAME = "DaonAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Daon TrustX";

    /**
     * Authenticator configuration property key for the Daon <b>login</b> process definition (PD).
     */
    public static final String DAON_LOGIN_PD = "daon_login_pd";

    /**
     * Configuration property key for the Daon <b>enrol</b> process definition (PD).
     */
    public static final String DAON_ENROL_PD = "daon_enrol_pd";

    /**
     * Adaptive-script runtime parameter asking the login step to <b>enrol</b> the user with Daon instead of
     * re-verifying them: the enrol process definition is sent in place of the login one, and the resulting
     * identity is recorded as the user's federated association.
     *
     * <p>Set per step from a conditional authentication script:</p>
     * <pre>
     * executeStep(3, {
     *     authenticationOptions: [ { idp: 'Daon TrustX Authenticator' } ],
     *     authenticatorParams: { federated: { 'Daon TrustX Authenticator': { enrol: 'true' } } }
     * }, {});
     * </pre>
     *
     * <p><b>The script only asks; the connector decides.</b> A user who already has a Daon enrolment is
     * refused with {@link DaonErrorConstants.ErrorMessage#ERROR_ALREADY_ENROLLED} however this parameter is
     * set — see {@code DaonAuthenticator#initiateAuthenticationRequest}. Without that check, anyone holding
     * the account's first-factor credentials could fail the face verification, be routed here, and bind
     * their own identity to the account.</p>
     */
    public static final String DAON_RUNTIME_PARAM_ENROL = "enrol";

    /**
     * Authenticator configuration property key holding the UUID of the referenced Daon IDP connection.
     */
    public static final String DAON_IDP_ID = "daon_idp_id";

    /**
     * Internal authenticator-property key used to carry the resolved process definition into
     * {@code getAdditionalQueryParams()} for the executor (registration / recovery) flows.
     */
    public static final String DAON_SELECTED_PD = "daon_selected_pd";

    /**
     * Property key carrying the fully built OIDC {@code claims} request parameter through the
     * authenticator properties, so {@code getAdditionalQueryParams()} only has to read it.
     *
     * <p>The parameter is built up-front in the executor's request preparation rather than inside
     * {@code getAdditionalQueryParams()} (whose signature cannot report a failure) precisely so that a
     * claims request which cannot be built fails the flow instead of silently dropping the
     * value-requests Daon is meant to verify the user's known attributes against.</p>
     */
    public static final String DAON_CLAIMS_REQUEST = "daon_claims_request";

    /**
     * Property key used to carry the resolved {@code login_hint} (Daon {@code preferred_username})
     * into {@code getAdditionalQueryParams()} for the password recovery face-auth flow. It doubles as
     * the <b>expected</b> identity the returned ID token is checked against — see
     * {@code DaonJwtUtil.isExpectedSubject}.
     */
    public static final String DAON_LOGIN_HINT = "daon_login_hint";

    /**
     * Authentication-context property holding the Daon subject the login step expects Daon to verify —
     * the enrolled user's {@code preferred_username} from their federated association, resolved when the
     * authorize request is built and read back when the callback is processed.
     *
     * <p>It is stashed on the context (rather than resolved again at the callback) so the identity the
     * response is bound to is the very one the {@code login_hint} was built from.</p>
     */
    public static final String DAON_EXPECTED_SUBJECT = "daon_expected_subject";

    /**
     * Authentication-context property holding the domain-qualified username of the local user an enrolment
     * request is enrolling (see {@link #DAON_RUNTIME_PARAM_ENROL}). A non-blank value marks the in-flight
     * request as an enrolment, so the callback records a new federated association instead of asserting a
     * match against an existing one.
     *
     * <p>Stashed when the authorize request is built — where the identified local user is unambiguously the
     * subject of the preceding step — rather than resolved again at the callback, by which point the
     * context's last authenticated user is the federated Daon identity.</p>
     */
    public static final String DAON_ENROLLING_USER = "daon_enrolling_user";

    /**
     * Authentication-context property holding the tenant domain of the local user an enrolment request is
     * enrolling, stashed alongside {@link #DAON_ENROLLING_USER}.
     *
     * <p>The federated association is stored against (username, userstore domain, <b>tenant</b>), so the
     * enrolment must write it under the same tenant the login step later reads it back with — the
     * <b>user's</b> tenant. That is not necessarily the authentication context's tenant, which is the
     * service provider's: in a B2B/organization login the two differ, and writing under one while reading
     * under the other leaves the account looking permanently not-enrolled.</p>
     *
     * <p>Stashed at request-build time for the same reason as {@link #DAON_ENROLLING_USER}: by the callback
     * the context's last authenticated user is the federated Daon identity, whose tenant is not the local
     * user's.</p>
     */
    public static final String DAON_ENROLLING_USER_TENANT = "daon_enrolling_user_tenant";

    /**
     * Flow-context property keys carrying the Daon federated association (IDP name + Daon subject /
     * preferred_username) from {@code DaonExecutor} to {@code DaonFederatedAssociationListener}, which
     * persists it once the flow completes and the user ID is available. The verification state lives in
     * the federated association store (IDP_USER_ID) — no custom user claims are required.
     */
    public static final String DAON_FED_IDP_NAME = "daon_fed_idp_name";
    public static final String DAON_FED_SUBJECT = "daon_fed_subject";

    /**
     * Flow type strings returned by {@code FlowExecutionContext.getFlowType()}.
     */
    public static final String FLOW_TYPE_PASSWORD_RECOVERY = "PASSWORD_RECOVERY";
    public static final String FLOW_TYPE_REGISTRATION = "REGISTRATION";
    public static final String FLOW_TYPE_INVITED_USER_REGISTRATION = "INVITED_USER_REGISTRATION";

    /*
     * Default targets for the halves of Daon's combined family_name_and_given_name, used only when the
     * connection maps no local claim for the corresponding Daon name claim. A mapped name claim wins — see
     * DaonExecutor#populateNameClaims.
     */
    public static final String WSO2_LASTNAME_CLAIM_URI = "http://wso2.org/claims/lastname";
    public static final String WSO2_GIVENNAME_CLAIM_URI = "http://wso2.org/claims/givenname";
}
