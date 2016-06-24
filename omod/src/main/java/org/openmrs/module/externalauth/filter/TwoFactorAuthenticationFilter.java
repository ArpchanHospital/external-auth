package org.openmrs.module.externalauth.filter;

import org.apache.commons.codec.binary.Base64;
import org.openmrs.api.context.Context;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.Charset;

public class TwoFactorAuthenticationFilter implements Filter {

    private OTPRestClient otpRestClient = new OTPRestClient();

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
                            String[] userAndPass = decodeAndSplitAuthorizationHeader(authCredentials);
                            otpRestClient.sendOTP(userAndPass[0]);
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
                        String[] userAndPass = decodeAndSplitAuthorizationHeader(authCredentials);
                        if (validateOTP(userAndPass[0], userAndPass[2])) {
                            httpRequest.getSession().removeAttribute("authOne");
                            Context.authenticate(userAndPass[0], userAndPass[1]);
                        } else {
                            HttpServletResponse httpServletResponse = (HttpServletResponse) response;
                            httpServletResponse.setStatus(401);
                            return;
                        }
                    } catch (Exception ex) {
                        // This filter never stops execution. If the user failed to
                        // authenticate, that will be caught later.
                        ex.printStackTrace();
                    }

                }
            }

        }

        // continue with the filter chain in all circumstances
        filterChain.doFilter(request, response);
    }

    private boolean authCredentialsContainsOTP(String authCredentials) {
        return (decodeAndSplitAuthorizationHeader(authCredentials).length == 3);
    }

    private String[] decodeAndSplitAuthorizationHeader(String encodedString) {
        encodedString = encodedString.substring(6); // remove the leading "Basic "
        String decoded = new String(Base64.decodeBase64(encodedString), Charset.forName("UTF-8"));
        return decoded.split(":");
    }

    private boolean validateOTP(String userName, String otp) {
        return otpRestClient.validateOTP(userName, otp);
    }

    private boolean firstLevelAuth(String authCredentials) throws IOException {
        boolean isAuthenticated = false;
        try {
            String[] userAndPass = decodeAndSplitAuthorizationHeader(authCredentials);
            Context.authenticate(userAndPass[0], userAndPass[1]);
            isAuthenticated = Context.isAuthenticated();
            if (isAuthenticated) {
                Context.logout();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return isAuthenticated;
    }

    @Override
    public void destroy() {

    }
}
