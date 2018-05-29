package com.axway.dynamic.ssoagent;

import java.io.*;
import java.security.Principal;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import groovy.lang.Binding;
import groovy.util.GroovyScriptEngine;
import groovy.util.ResourceException;
import groovy.util.ScriptException;

public class SSOAgentFilter implements Filter {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSOAgentFilter.class);

    private final String scriptName;
    private final GroovyScriptEngine engine;

    SSOAgentFilter(String scriptFileName) throws IOException {
        File script = new File(scriptFileName);
        if (!script.isFile() || !script.canRead()) {
            throw new IOException("Groovy script file '" + scriptFileName + "' did not construct a valid java File instance");
        }
        scriptName = script.getName();
        engine = new GroovyScriptEngine(script.getAbsolutePath());
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;

        String username = "";
        Set<String> roles = new HashSet<>();

        Binding binding = new Binding();
        binding.setProperty("request", request);
        binding.setProperty("response", response);
        binding.setProperty("username", username);
        binding.setProperty("roles", roles);

        try {
            engine.run(scriptName, binding);
        } catch (ResourceException | ScriptException e) {
            LOGGER.warn("Error occurred when executing script", e);
        }

        username = (String) binding.getProperty("username");
        roles = (Set<String>) binding.getProperty("roles");
        request = new AuthenticatedHttpServletRequestWrapper(httpRequest, username, roles);

        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // should be empty, use initialization through constructor
    }

    @Override
    public void destroy() {
        // should be empty, if a release mechanism is needed, use an ad-hoc method to be called by the activator
    }

    private static class AuthenticatedHttpServletRequestWrapper extends HttpServletRequestWrapper {
        private final Principal principal;
        private final Set<String> roles;

        private AuthenticatedHttpServletRequestWrapper(HttpServletRequest request, String username, Set<String> roles) {
            super(request);
            principal = new PrincipalImpl(username);
            this.roles = roles;
        }

        @Override
        public Principal getUserPrincipal() {
            return principal;
        }

        @Override
        public boolean isUserInRole(String adiRole) {
            return roles.contains(adiRole);
        }
    }

    private static class PrincipalImpl implements Principal {
        private final String name;

        private PrincipalImpl(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public boolean equals(Object obj) {
            return (this == obj) || ((obj instanceof PrincipalImpl) && name.equals(((PrincipalImpl) obj).name));
        }

        @Override
        public int hashCode() {
            return name.hashCode();
        }

        @Override
        public String toString() {
            return name;
        }
    }
}
