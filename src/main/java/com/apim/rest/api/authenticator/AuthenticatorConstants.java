/*
 *  Copyright (c) 2022, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

import java.util.regex.Pattern;

public final class AuthenticatorConstants {

    public static final String PROTOCOL_HEADERS = "org.apache.cxf.message.Message.PROTOCOL_HEADERS";
    public static final String SUPER_TENANT_SUFFIX = "@carbon.super";
    public static final Pattern REGEX_BEARER_PATTERN = Pattern.compile("Bearer\\s");
    public static final String AUTH_HEADER_NAME = "Authorization";
    public static final String ERROR_SCOPE_VALIDATION_FAILED = "You cannot access API as scope validation failed";
    public static final String ERROR_TOKEN_INVALID = "Provided access token is invalid";
    public static final String OAUTH2_AUTHENTICATION = "oauth2";

}
