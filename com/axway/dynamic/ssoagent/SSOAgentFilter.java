package com.axway.dynamic.ssoagent;

import groovy.util.ResourceException;
import java.io.*;
import java.security.Principal;
import java.util.*;
import java.util.logging.Level;

import javax.servlet.*;
import javax.servlet.http.*;

public class SSOAgentFilter implements Filter {

    private final File script;
    private final groovy.util.GroovyScriptEngine engine;

    public SSOAgentFilter(String script) throws IOException {
        
        this.script = new File(script);
        if (this.script == null || !this.script.isFile() || !this.script.canRead()) {
            throw new IOException("Groovy script file '" + script + "' did not construct a valid java File instance");
        }
        String roots[] = new String[] {
          this.script.getAbsolutePath()
        };
        engine = new groovy.util.GroovyScriptEngine(roots);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;

        Set<String> adiRoles = new HashSet<String>();
        String username = "";
                
        groovy.lang.Binding binding = new groovy.lang.Binding();
        binding.setProperty("request", request);
        binding.setProperty("response", response);
        binding.setProperty("chain", chain);
        binding.setProperty("username", username);
        binding.setProperty("adiRoles", adiRoles);
        
        try {
            engine.run(script.getName(), binding);
            adiRoles = (Set<String>) binding.getProperty("adiRoles");
            username = (String) binding.getProperty("username");

            request = new AuthenticatedHttpServletRequestWrapper(httpRequest, username, adiRoles);
        } catch (ResourceException ex) {
            java.util.logging.Logger.getLogger(SSOAgentFilter.class.getName()).log(Level.SEVERE, null, ex);
        } catch (groovy.util.ScriptException ex) {
            java.util.logging.Logger.getLogger(SSOAgentFilter.class.getName()).log(Level.SEVERE, null, ex);
        }
        
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

        public AuthenticatedHttpServletRequestWrapper(HttpServletRequest request, String username, Set<String> roles) {
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
