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

package org.wso2.carbon.identity.verification.daon.connector.web;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonClientException;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.AUTHORIZATION_ENDPOINT_URL;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIMS_PARAM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_VALUE_MEMBER;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_DOCUMENT_CLASSIFICATION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_DOCUMENT_DATE_OF_EXPIRY;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_DOCUMENT_NUMBER;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_DOCUMENT_PERSONAL_NUMBER;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_DOCUMENT_TYPE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_FAMILY_NAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_FAMILY_NAME_AND_GIVEN_NAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_GIVEN_NAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLIENT_ID;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLIENT_SECRET;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.GRANT_TYPE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ID_TOKEN_CONTAINER;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.REDIRECT_URI;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.RESPONSE_TYPE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.RESPONSE_TYPE_CODE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.SCOPE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.STATE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.TOKEN_ENDPOINT_URL;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.TRUST_FRAMEWORK;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.TRUST_FRAMEWORK_VALUE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.VERIFICATION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.VERIFIED_CLAIMS;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_BUILDING_DAON_AUTH_URI;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_BUILDING_DAON_TOKEN_URI;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_CREATING_RESPONSE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_EXCHANGING_CODE_FOR_TOKENS;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_INVALID_CLIENT_CREDENTIALS;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_INVALID_OR_EXPIRED_CODE;

/**
 * API client for the Daon TrustX OIDC integration.
 */
public class DaonAPIClient {

    /**
     * Builds the OIDC authorization URL that the user's browser should be redirected to.
     * Includes a {@code claims} parameter requesting verified claims for the specified Daon claim names.
     *
     * @param idVConfigPropertyMap Configuration properties of the IdV Provider.
     * @param state                A random UUID used as CSRF token.
     * @param daonClaimNames       Daon claim names (from IdVProvider claim mappings) to request.
     * @return The full OIDC authorization URL string.
     * @throws DaonServerException If the URL cannot be built.
     */
    public static String buildAuthorizationUrl(Map<String, String> idVConfigPropertyMap, String state,
                                                List<String> daonClaimNames, String redirectUri)
            throws DaonServerException {

        String authEndpoint = idVConfigPropertyMap.get(AUTHORIZATION_ENDPOINT_URL);
        String clientId = idVConfigPropertyMap.get(CLIENT_ID);
        String scope = idVConfigPropertyMap.get(SCOPE);

        try {
            URIBuilder builder = new URIBuilder(authEndpoint)
                    .addParameter(RESPONSE_TYPE, RESPONSE_TYPE_CODE)
                    .addParameter(CLIENT_ID, clientId)
                    .addParameter(SCOPE, scope)
                    .addParameter(STATE, state)
                    .addParameter(REDIRECT_URI, redirectUri)
                    .addParameter(CLAIMS_PARAM, buildClaimsParam(daonClaimNames));
            return builder.build().toString();
        } catch (URISyntaxException e) {
            throw new DaonServerException(ERROR_BUILDING_DAON_AUTH_URI.getCode(),
                    ERROR_BUILDING_DAON_AUTH_URI.getMessage(), e);
        }
    }

    /**
     * Builds the OIDC {@code claims} request parameter JSON for the given Daon claim names.
     *
     * <p>If the list contains {@code given_name} or {@code family_name},
     * {@code family_name_and_given_name} is automatically added as a fallback. Some identity
     * documents store the full name as a single field; without this fallback Daon would return
     * neither name claim for those documents.
     *
     * <p>When a claim's value is already known before Daon is triggered (e.g. an attribute the user
     * populated earlier in a registration flow), it is sent as an OIDC value-request
     * ({@code {"value": "..."}}) instead of {@code null}, so Daon verifies against that value.</p>
     *
     * <pre>
     * {
     *   "id_token": {
     *     "verified_claims": {
     *       "verification": { "trust_framework": "daon-identify-1" },
     *       "claims": { "given_name": {"value": "JOHN"}, "family_name": null, ... }
     *     }
     *   }
     * }
     * </pre>
     */
    private static final List<String> DOCUMENT_CLAIMS = Arrays.asList(
            CLAIM_DOCUMENT_TYPE,
            CLAIM_DOCUMENT_CLASSIFICATION,
            CLAIM_DOCUMENT_DATE_OF_EXPIRY,
            CLAIM_DOCUMENT_NUMBER,
            CLAIM_DOCUMENT_PERSONAL_NUMBER
    );

    public static String buildClaimsParam(List<String> daonClaimNames) {

        return buildClaimsParam(daonClaimNames, Collections.emptyMap());
    }

    /**
     * Builds the OIDC {@code claims} request parameter, sending a value-request
     * ({@code {"value": "..."}}) for any Daon claim name present in {@code claimValues} and
     * {@code null} for the rest.
     *
     * @param daonClaimNames Daon claim names to request.
     * @param claimValues    Pre-known values keyed by Daon claim name; may be empty.
     */
    public static String buildClaimsParam(List<String> daonClaimNames, Map<String, String> claimValues) {

        Map<String, String> values = claimValues != null ? claimValues : Collections.emptyMap();
        List<String> effectiveNames = new ArrayList<>(daonClaimNames);
        if ((effectiveNames.contains(CLAIM_GIVEN_NAME) || effectiveNames.contains(CLAIM_FAMILY_NAME))
                && !effectiveNames.contains(CLAIM_FAMILY_NAME_AND_GIVEN_NAME)) {
            effectiveNames.add(CLAIM_FAMILY_NAME_AND_GIVEN_NAME);
        }
        for (String docClaim : DOCUMENT_CLAIMS) {
            if (!effectiveNames.contains(docClaim)) {
                effectiveNames.add(docClaim);
            }
        }

        JSONObject claimsObj = new JSONObject();
        for (String claimName : effectiveNames) {
            String value = values.get(claimName);
            if (value != null && !value.trim().isEmpty()) {
                claimsObj.put(claimName, new JSONObject().put(CLAIM_VALUE_MEMBER, value));
            } else {
                claimsObj.put(claimName, JSONObject.NULL);
            }
        }
        JSONObject verification = new JSONObject().put(TRUST_FRAMEWORK, TRUST_FRAMEWORK_VALUE);
        JSONObject verifiedClaims = new JSONObject()
                .put(VERIFICATION, verification)
                .put(CLAIMS_PARAM, claimsObj);
        JSONObject idToken = new JSONObject().put(VERIFIED_CLAIMS, verifiedClaims);
        return new JSONObject().put(ID_TOKEN_CONTAINER, idToken).toString();
    }

    /**
     * Exchanges an authorization code for tokens at the Daon token endpoint.
     *
     * @param idVConfigPropertyMap Configuration properties of the IdV Provider.
     * @param code                 The authorization code received from Daon.
     * @return A JSONObject containing at minimum {@code access_token} and {@code id_token}.
     * @throws DaonServerException If a server-side error occurs.
     * @throws DaonClientException If the code is invalid or credentials are wrong.
     */
    public static JSONObject exchangeCodeForTokens(Map<String, String> idVConfigPropertyMap, String code,
                                                    String redirectUri)
            throws DaonServerException, DaonClientException {

        String tokenEndpoint = idVConfigPropertyMap.get(TOKEN_ENDPOINT_URL);
        String clientId = idVConfigPropertyMap.get(CLIENT_ID);
        String clientSecret = idVConfigPropertyMap.get(CLIENT_SECRET);

        try {
            String requestBody = GRANT_TYPE + "=" + GRANT_TYPE_AUTHORIZATION_CODE
                    + "&" + "code" + "=" + encode(code)
                    + "&" + REDIRECT_URI + "=" + encode(redirectUri);

            HttpResponse response = DaonWebUtils.httpPostWithBasicAuth(
                    clientId, clientSecret, tokenEndpoint, requestBody);

            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_OK) {
                return getJsonObject(response);
            } else if (statusCode == HttpStatus.SC_UNAUTHORIZED) {
                throw new DaonClientException(ERROR_INVALID_CLIENT_CREDENTIALS.getCode(),
                        ERROR_INVALID_CLIENT_CREDENTIALS.getMessage());
            } else if (statusCode == HttpStatus.SC_BAD_REQUEST) {
                throw new DaonClientException(ERROR_INVALID_OR_EXPIRED_CODE.getCode(),
                        ERROR_INVALID_OR_EXPIRED_CODE.getMessage());
            } else {
                throw new DaonServerException(ERROR_EXCHANGING_CODE_FOR_TOKENS.getCode(),
                        String.format(ERROR_EXCHANGING_CODE_FOR_TOKENS.getMessage(), statusCode));
            }
        } catch (URISyntaxException e) {
            throw new DaonServerException(ERROR_BUILDING_DAON_TOKEN_URI.getCode(),
                    ERROR_BUILDING_DAON_TOKEN_URI.getMessage(), e);
        }
    }

    /**
     * Exchanges an authorization code for tokens using a fully-qualified token endpoint URL.
     *
     * <p>Use this overload when the caller already has the full token endpoint URL (e.g. from
     * an authenticator property), rather than a base URL that needs a path appended.
     *
     * @param tokenEndpointUrl Full token endpoint URL.
     * @param clientId         OAuth2 client ID.
     * @param clientSecret     OAuth2 client secret.
     * @param code             The authorization code received from the authorization server.
     * @param redirectUri      The redirect URI used in the original authorization request.
     * @return A JSONObject containing at minimum {@code access_token} and {@code id_token}.
     * @throws DaonServerException If a server-side error occurs.
     * @throws DaonClientException If the code is invalid or credentials are wrong.
     */
    public static JSONObject exchangeCodeForTokens(String tokenEndpointUrl, String clientId,
                                                    String clientSecret, String code, String redirectUri)
            throws DaonServerException, DaonClientException {

        try {
            String requestBody = GRANT_TYPE + "=" + GRANT_TYPE_AUTHORIZATION_CODE
                    + "&" + "code" + "=" + encode(code)
                    + "&" + REDIRECT_URI + "=" + encode(redirectUri);

            HttpResponse response = DaonWebUtils.httpPostWithBasicAuth(
                    clientId, clientSecret, tokenEndpointUrl, requestBody);

            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_OK) {
                return getJsonObject(response);
            } else if (statusCode == HttpStatus.SC_UNAUTHORIZED) {
                throw new DaonClientException(ERROR_INVALID_CLIENT_CREDENTIALS.getCode(),
                        ERROR_INVALID_CLIENT_CREDENTIALS.getMessage());
            } else if (statusCode == HttpStatus.SC_BAD_REQUEST) {
                throw new DaonClientException(ERROR_INVALID_OR_EXPIRED_CODE.getCode(),
                        ERROR_INVALID_OR_EXPIRED_CODE.getMessage());
            } else {
                throw new DaonServerException(ERROR_EXCHANGING_CODE_FOR_TOKENS.getCode(),
                        String.format(ERROR_EXCHANGING_CODE_FOR_TOKENS.getMessage(), statusCode));
            }
        } catch (URISyntaxException e) {
            throw new DaonServerException(ERROR_BUILDING_DAON_TOKEN_URI.getCode(),
                    ERROR_BUILDING_DAON_TOKEN_URI.getMessage(), e);
        }
    }

    /**
     * Decodes the payload of a JWT ID token without verification (claims extraction only).
     *
     * @param idToken The dot-separated JWT string.
     * @return A JSONObject containing the ID token payload claims.
     */
    public static JSONObject parseIdToken(String idToken) {

        String[] parts = idToken.split("\\.");
        if (parts.length < 2) {
            return new JSONObject();
        }
        byte[] payloadBytes = Base64.getUrlDecoder().decode(addPadding(parts[1]));
        return new JSONObject(new String(payloadBytes, StandardCharsets.UTF_8));
    }

    private static JSONObject getJsonObject(HttpResponse response) throws DaonServerException {

        try {
            HttpEntity entity = response.getEntity();
            String jsonResponse = EntityUtils.toString(entity);
            return new JSONObject(jsonResponse);
        } catch (IOException e) {
            throw new DaonServerException(ERROR_CREATING_RESPONSE.getCode(),
                    ERROR_CREATING_RESPONSE.getMessage());
        }
    }

    private static String encode(String value) throws URISyntaxException {

        try {
            return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (java.io.UnsupportedEncodingException e) {
            throw new URISyntaxException(value, "Unable to URL-encode value");
        }
    }

    private static String addPadding(String base64) {

        int remainder = base64.length() % 4;
        if (remainder == 2) {
            return base64 + "==";
        } else if (remainder == 3) {
            return base64 + "=";
        }
        return base64;
    }
}
