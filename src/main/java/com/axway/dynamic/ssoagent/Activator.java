package com.axway.dynamic.ssoagent;

import java.util.*;
import javax.servlet.*;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.osgi.service.http.whiteboard.HttpWhiteboardConstants.HTTP_WHITEBOARD_FILTER_PATTERN;

public class Activator implements BundleActivator {
    private static final Logger LOGGER = LoggerFactory.getLogger(Activator.class);
    private static final String SCRIPT = "com.axway.dynamic.ssoagent.script";

    private ServiceRegistration<Filter> registration;

    @Override
    public void start(BundleContext context) throws Exception {
        Filter authenticationFilter = createAuthenticationFilter(context);
        if (authenticationFilter != null) {
            registerAuthenticationFilter(context, authenticationFilter);
        }
    }

    @Override
    public void stop(BundleContext context) throws Exception {
        unregisterAuthenticationFilter();
    }

    private Filter createAuthenticationFilter(BundleContext context) throws Exception {
        String scriptFileName = context.getProperty(SCRIPT);
        if (scriptFileName == null) {
            LOGGER.warn("Property {} has not be specified. DynamicSSO filter won't be installed", SCRIPT);
            return null;
        } else {
            return new SSOAgentFilter(scriptFileName);
        }
    }

    private void registerAuthenticationFilter(BundleContext context, Filter authenticationFilter) {
        Dictionary<String, Object> props = new Hashtable<>();
        props.put(HTTP_WHITEBOARD_FILTER_PATTERN, "/*");
        registration = context.registerService(Filter.class, authenticationFilter, props);
        LOGGER.info("Authentication filter has been registered");
    }

    private void unregisterAuthenticationFilter() {
        if (registration != null) {
            registration.unregister();
            LOGGER.info("Authentication filter has been unregistered");
        }
    }
}
