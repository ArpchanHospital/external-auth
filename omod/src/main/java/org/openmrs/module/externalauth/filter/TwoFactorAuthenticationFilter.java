package org.openmrs.module.externalauth.filter;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.api.context.Context;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.Charset;

public class TwoFactorAuthenticationFilter implements Filter {

    protected final Log log = LogFactory.getLog(getClass());

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException,
            ServletException {
        // skip if the session has timed out, we're already authenticated, or it's not an HTTP request
        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            if (!Context.isAuthenticated()) {
                String authCredentials = httpRequest.getHeader("Authorization");
                Object authOne = httpRequest.getSession().getAttribute("authOne");
                if (authCredentials == null) {
                    if (authOne != null) {
                        httpRequest.getSession().removeAttribute("authOne");
                    }
                    filterChain.doFilter(request, response);
                    return;
                }
                if (authOne == null) {
                    if (!authCredentialsContainsOTP(authCredentials)) {
                        if (firstLevelAuth(authCredentials)) {
                            HttpServletResponse httpServletResponse = (HttpServletResponse) response;
                            httpServletResponse.setStatus(204);
                            return;
                        } else {
                            filterChain.doFilter(request, response);
                            return;
                        }
                    } else {
                        httpRequest.getSession().setAttribute("authOne", true);
                        authOne = httpRequest.getSession().getAttribute("authOne");
                    }
                }

                if (authOne != null) {
                    try {
                        authCredentials = authCredentials.substring(6); // remove the leading "Basic "
                        String decoded = new String(Base64.decodeBase64(authCredentials), Charset.forName("UTF-8"));
                        String[] userAndPass = decoded.split(":");
                        if (validateOTP(userAndPass[2])) {
                            httpRequest.getSession().removeAttribute("authOne");
                            Context.authenticate(userAndPass[0], userAndPass[1]);
                        } else {
                            HttpServletResponse httpServletResponse = (HttpServletResponse) response;
                            httpServletResponse.setStatus(401);
                            return;
                        }
                    }
                    catch (Exception ex) {
                        // This filter never stops execution. If the user failed to
                        // authenticate, that will be caught later.
                    }

                }
            }

        }

        // continue with the filter chain in all circumstances
        filterChain.doFilter(request, response);
    }

    private boolean authCredentialsContainsOTP(String authCredentials) {
        authCredentials = authCredentials.substring(6); // remove the leading "Basic "
        String decoded = new String(Base64.decodeBase64(authCredentials), Charset.forName("UTF-8"));
        String[] credentials = decoded.split(":");
        return (credentials.length == 3);
    }

    private boolean validateOTP(String otp) {
        return otp.equalsIgnoreCase("123456");
    }

    private boolean firstLevelAuth(String authCredentials) throws IOException {
        boolean isAuthenticated = false;
        try {
            authCredentials = authCredentials.substring(6); // remove the leading "Basic "
            String decoded = new String(Base64.decodeBase64(authCredentials), Charset.forName("UTF-8"));
            String[] userAndPass = decoded.split(":");
            Context.authenticate(userAndPass[0], userAndPass[1]);
            isAuthenticated = Context.isAuthenticated();
            if (isAuthenticated) {
                Context.logout();
            }
        }
        catch (Exception e) {

        }
        return isAuthenticated;
    }

    @Override
    public void destroy() {

    }
}
