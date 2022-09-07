/*
 *  Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.apim.rest.api.authenticator;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIMgtAuthorizationFailedException;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.impl.utils.JWTUtil;
import org.wso2.carbon.apimgt.rest.api.common.RestApiCommonUtil;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.apimgt.rest.api.common.RestAPIAuthenticator;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ISKMAuthenticationImpl implements RestAPIAuthenticator {

    private static final Log log = LogFactory.getLog(ISKMAuthenticationImpl.class);
    private static final String JWKS_URL = System.getProperty("jwksURL");
    private JWKSet jwkSet;

    @Override
    public boolean authenticate(HashMap<String, Object> message) throws APIMgtAuthorizationFailedException {

        AccessTokenInfo tokenInfo;
        SignedJWT signedJWT;
        Boolean isTokenValidated;
        String accessToken = extractOAuthAccessTokenFromMessage(message,
                AuthenticatorConstants.REGEX_BEARER_PATTERN, AuthenticatorConstants.AUTH_HEADER_NAME);

        if (StringUtils.countMatches(accessToken, APIConstants.DOT) != 2) {
            log.error("Invalid JWT token. The expected token format is <header.payload.signature>");
            return false;
        }

        try {
            signedJWT = SignedJWT.parse(accessToken);
            // Get the token information, and set token validity by checking the expiry time
            tokenInfo = getTokenInfo(signedJWT.getJWTClaimsSet());
            // Validates the token signature
            isTokenValidated = validateToken(signedJWT);
        } catch (ParseException e) {
            log.error("Error while retrieving token information for token: " + accessToken, e);
            return false;
        }

        if (tokenInfo != null && tokenInfo.isTokenValid() && isTokenValidated.equals(true)) {

            // If access token is valid then we will perform scope check for given resource.
            if (RestApiCommonUtil.validateScopes(message, tokenInfo)) {

            String tenantDomain = MultitenantUtils.getTenantDomain(tokenInfo.getEndUserName());
            int tenantId;

            try {
                PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
                RealmService realmService =
                        (RealmService) carbonContext.getOSGiService(RealmService.class, null);

                String username = tokenInfo.getEndUserName();
                if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                    //when the username is an email in supertenant, it has at least 2 occurrences of '@'
                    long count = username.chars().filter(ch -> ch == '@').count();
                    //in the case of email, there will be more than one '@'
                    boolean isEmailUsernameEnabled = Boolean.parseBoolean(CarbonUtils.getServerConfiguration().
                            getFirstProperty("EnableEmailUserName"));
                    if (isEmailUsernameEnabled || (username.endsWith(AuthenticatorConstants.SUPER_TENANT_SUFFIX)
                            && count <= 1)) {
                        username = MultitenantUtils.getTenantAwareUsername(username);
                    }
                }
                if (log.isDebugEnabled()) {
                    log.debug("username = " + username);
                }
                tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
                carbonContext.setTenantDomain(tenantDomain);
                carbonContext.setTenantId(tenantId);
                carbonContext.setUsername(username);
                if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                    APIUtil.loadTenantConfigBlockingMode(tenantDomain);
                }
                return true;
            } catch (UserStoreException e) {
                log.error("Error while retrieving tenant id for tenant domain: " + tenantDomain, e);
            }
            } else {
                log.error(AuthenticatorConstants.ERROR_SCOPE_VALIDATION_FAILED);
            }
        } else {
            log.error(AuthenticatorConstants.ERROR_TOKEN_INVALID);
        }
        return false;
    }

    /**
     * Extract the required token information from the JWT access token
     * @param jwtClaimsSet
     * @return
     */
    public AccessTokenInfo getTokenInfo(JWTClaimsSet jwtClaimsSet) {

        AccessTokenInfo accessTokenInfo = new AccessTokenInfo();
        String endUserName = APIUtil.getUserNameWithTenantSuffix(jwtClaimsSet.getSubject());

        accessTokenInfo.setIssuedTime(jwtClaimsSet.getIssueTime().getTime());
        accessTokenInfo.setValidityPeriod(jwtClaimsSet.getExpirationTime().getTime());
        accessTokenInfo.setEndUserName(endUserName);
        accessTokenInfo.setScope(jwtClaimsSet.getClaim("scope").toString().split(","));
        accessTokenInfo.setTokenValid(validateTokenExpiry(jwtClaimsSet));

        return accessTokenInfo;
    }

    /**
     * Extracting the access token from the message
     * @param message
     * @param pattern
     * @param authHeaderName
     * @return
     */
    protected static String extractOAuthAccessTokenFromMessage(HashMap<String, Object> message, Pattern pattern,
                                                     String authHeaderName) {

        String authHeader = null;
        ArrayList authHeaders = (ArrayList) ((TreeMap) (message.get(AuthenticatorConstants.PROTOCOL_HEADERS)))
                .get(authHeaderName);
        if (authHeaders == null)
            return null;

        String headerString = authHeaders.get(0).toString();
        Matcher matcher = pattern.matcher(headerString);
        if (matcher.find()) {
            authHeader = headerString.substring(matcher.end());
        }
        return authHeader;
    }

    /**
     * Validate the token expiry time
     * @param jwtClaimsSet
     * @return
     */
    protected boolean validateTokenExpiry(JWTClaimsSet jwtClaimsSet) {

        long timestampSkew =
                ServiceReferenceHolder.getInstance().getOauthServerConfiguration().getTimeStampSkewInSeconds();
        Date now = new Date();
        Date exp = jwtClaimsSet.getExpirationTime();
        return exp == null || DateUtils.isAfter(exp, now, timestampSkew);
    }

    public boolean validateToken(SignedJWT signedJWT) {

        Boolean isValidated = false;

        isValidated = validateSignature(signedJWT);

        if (log.isDebugEnabled() && Boolean.FALSE.equals(isValidated)) {
                log.debug("Access token signature verification failed");
        }

        return isValidated;
    }

    /**
     * Validate token signature
     * @param signedJWT
     * @return
     * @throws APIManagementException
     */
    protected boolean validateSignature(SignedJWT signedJWT) {

        try {
            String keyID = signedJWT.getHeader().getKeyID();
            if (org.apache.commons.lang.StringUtils.isNotEmpty(keyID)) {
                if (StringUtils.isNotEmpty(JWKS_URL)) {
                    // Check JWKSet Available in Cache
                    if (jwkSet == null) {
                        jwkSet = retrieveJWKSet();
                    }
                    if (jwkSet.getKeyByKeyId(keyID) == null) {
                        jwkSet = retrieveJWKSet();
                    }
                    if (jwkSet.getKeyByKeyId(keyID) instanceof RSAKey) {
                        RSAKey keyByKeyId = (RSAKey) jwkSet.getKeyByKeyId(keyID);
                        RSAPublicKey rsaPublicKey = keyByKeyId.toRSAPublicKey();
                        if (rsaPublicKey != null) {
                            return JWTUtil.verifyTokenSignature(signedJWT, rsaPublicKey);
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("Key Algorithm not supported");
                        }
                        return false; // return false to produce 401 unauthenticated response
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Could not find system property jwksURL");
                    }
                    return false;
                }
            }
        } catch (ParseException | JOSEException | IOException e) {
            log.error("Error while parsing JWT", e);
        }
        return false;
    }


    private JWKSet retrieveJWKSet() throws IOException, ParseException {

        String jwksInfo = JWTUtil
                .retrieveJWKSConfiguration(JWKS_URL);
        jwkSet = JWKSet.parse(jwksInfo);
        return jwkSet;
    }

    @Override
    public boolean canHandle(HashMap<String, Object> message) {

        String accessToken = extractOAuthAccessTokenFromMessage(message,
                AuthenticatorConstants.REGEX_BEARER_PATTERN, AuthenticatorConstants.AUTH_HEADER_NAME);

        if (StringUtils.isNotEmpty(accessToken) && accessToken.length() < 64) {
            return false;
        }

        return true;
    }

    @Override
    public String getAuthenticationType() {
        return AuthenticatorConstants.OAUTH2_AUTHENTICATION;
    }

    @Override
    public int getPriority(HashMap<String, Object> message) {
        return 0;
    }
}
