package org.openmrs.module.externalauth.filter;

import org.apache.commons.codec.binary.Base64;
import org.openmrs.Role;
import org.openmrs.User;
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
import java.util.Set;

public class TwoFactorAuthenticationFilter implements Filter {

    private OTPRestClient otpRestClient = new OTPRestClient();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        // skip if the session has timed out, we're already authenticated, or it's not an HTTP request
        if (request instanceof HttpServletRequest && !Context.isAuthenticated()) {
            HttpServletRequest httpServletRequest = (HttpServletRequest) request;
            HttpServletResponse httpServletResponse = (HttpServletResponse) response;

            String authorization = httpServletRequest.getHeader("Authorization");
            Object authOne = httpServletRequest.getSession().getAttribute("authOne");
            if (authorization == null) {
                if (authOne != null) {
                    httpServletRequest.getSession().removeAttribute("authOne");
                }
                filterChain.doFilter(request, response);
                return;
            }

            String[] credentials = decodeAndSplitAuthorization(authorization);
            boolean resendOTP = Boolean.valueOf(request.getParameter("resendOTP"));

            if (authOne == null && !resendOTP) {
                if (credentials.length == 2) {
                    if (verifyUserNameAndPassword(credentials[0], credentials[1])) {
                        if (!shouldBypass2FA()) {
                            Context.logout();
                            otpRestClient.sendOTP(credentials[0]);
                            httpServletResponse.setStatus(204);
                            return;
                        }
                    } else {
                        filterChain.doFilter(request, response);
                        return;
                    }
                } else {
                    httpServletRequest.getSession().setAttribute("authOne", true);
                    authOne = httpServletRequest.getSession().getAttribute("authOne");
                }
            }

            if (resendOTP) {
                String status = otpRestClient.resendOTP(credentials[0]);
                if ("max_resend_attempts_exceeded".equals(status)) {
                    httpServletRequest.getSession().removeAttribute("authOne");
                    httpServletResponse.setStatus(429); // Too many requests (https://tools.ietf.org/html/rfc6585)
                }
                return;
            }

            if (authOne != null) {
                try {
                    String status = validateOTP(credentials[0], credentials[2]);
                    switch (status) {
                        case "true":
                            httpServletRequest.getSession().removeAttribute("authOne");
                            Context.authenticate(credentials[0], credentials[1]);
                            break;
                        case "false":
                            httpServletResponse.setStatus(401);
                            return;
                        case "expired":
                            httpServletRequest.getSession().removeAttribute("authOne");
                            httpServletResponse.setStatus(410); // Gone
                            return;
                        default:
                            httpServletRequest.getSession().removeAttribute("authOne");
                            httpServletResponse.setStatus(429); // Too many requests (https://tools.ietf.org/html/rfc6585)
                            return;
                    }
                } catch (Exception ex) {
                    // This filter never stops execution. If the user failed to
                    // authenticate, that will be caught later.
                    ex.printStackTrace();
                }
            }
        }
        // continue with the filter chain in all circumstances
        filterChain.doFilter(request, response);
    }

    private boolean shouldBypass2FA() {
        User user = Context.getAuthenticatedUser();
        Set<Role> roles = user.getRoles();
        Role bypass2FA = Context.getUserService().getRole("bypass2FA");
        return roles.contains(bypass2FA);
    }

    private String[] decodeAndSplitAuthorization(String encodedString) {
        encodedString = encodedString.substring(6); // remove the leading "Basic "
        String decoded = new String(Base64.decodeBase64(encodedString), Charset.forName("UTF-8"));
        return decoded.split(":");
    }

    private String validateOTP(String userName, String otp) {
        return otpRestClient.validateOTP(userName, otp);
    }

    private boolean verifyUserNameAndPassword(String username, String password) throws IOException {
        boolean isAuthenticated = false;
        try {
            Context.authenticate(username, password);
            isAuthenticated = Context.isAuthenticated();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return isAuthenticated;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }
}
