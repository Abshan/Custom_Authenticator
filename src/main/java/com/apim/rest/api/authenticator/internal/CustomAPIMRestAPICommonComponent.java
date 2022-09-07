/*
 *
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

package com.apim.rest.api.authenticator.internal;

import com.apim.rest.api.authenticator.ISKMAuthenticationImpl;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.wso2.carbon.apimgt.impl.APIManagerConfigurationService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.apimgt.rest.api.common.RestAPIAuthenticator;

/**
 * This class implemented for Setting APIM Configuration Service
 */
@Component(name = "com.rest.api.authenticator.internal.component", immediate = true)
public class CustomAPIMRestAPICommonComponent {

    private static final Log log = LogFactory.getLog(CustomAPIMRestAPICommonComponent.class);
    private ServiceRegistration serviceRegistration = null;

    @Activate
    protected void activate(ComponentContext context) {
        BundleContext bundleContext = context.getBundleContext();
        serviceRegistration = bundleContext.registerService(RestAPIAuthenticator.class.getName(),
                new ISKMAuthenticationImpl(), null);
        log.info("CustomAPIMRestAPICommonComponent bundle is activated");
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        if (serviceRegistration != null) {
            serviceRegistration.unregister();
        }
    }

    @Reference(
            name = "api.manager.config.service",
            service = org.wso2.carbon.apimgt.impl.APIManagerConfigurationService.class,
            cardinality = org.osgi.service.component.annotations.ReferenceCardinality.MANDATORY,
            policy = org.osgi.service.component.annotations.ReferencePolicy.DYNAMIC,
            unbind = "unsetAPIManagerConfigurationService")
    protected void setAPIManagerConfigurationService(APIManagerConfigurationService configurationService) {

        log.debug("Setting APIM Configuration Service");
        CustomServiceReferenceHolder.getInstance().setAPIMConfigurationService(configurationService);
    }

    protected void unsetAPIManagerConfigurationService(APIManagerConfigurationService configurationService) {

        log.debug("Unsetting APIM Configuration Service");
        CustomServiceReferenceHolder.getInstance().setAPIMConfigurationService(null);
    }

    @Reference(
            name = "rest.api.authentication.service",
            cardinality = ReferenceCardinality.MULTIPLE,
            service = org.wso2.carbon.apimgt.rest.api.common.RestAPIAuthenticator.class,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeRestAPIAuthenticationService"
    )
    protected void addRestAPIAuthenticationService(RestAPIAuthenticator authenticator) {
        CustomServiceReferenceHolder.getInstance().addAuthenticator(authenticator);
    }

    protected void removeRestAPIAuthenticationService(RestAPIAuthenticator authenticator) {
        CustomServiceReferenceHolder.getInstance().removeAuthenticator(authenticator);
    }

    @Reference(
            name = "realm.service",
            cardinality = ReferenceCardinality.MANDATORY,
            service = org.wso2.carbon.user.core.service.RealmService.class,
            policy = ReferencePolicy.DYNAMIC,
            bind = "setRealmService",
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {
        CustomServiceReferenceHolder.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        CustomServiceReferenceHolder.setRealmService(null);
    }
}