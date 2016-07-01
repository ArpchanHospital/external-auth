package org.openmrs.module.externalauth.filter;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.web.client.RestOperations;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class OTPRestClientTest {

    @Mock
    private RestOperations restOperations;

    @InjectMocks
    private OTPRestClient otpRestClient;

    private static final String URL = "http://localhost:8058";

    @Test
    public void shouldCallSecurityAppToSendOTP() {
        otpRestClient.sendOTP("username");

        verify(restOperations, times(1)).getForObject(eq(URL + "/send?userName=username"), eq(String.class));
    }

    @Test
    public void shouldCallSecurityAppToValidateOTP() {
        String validateURL = URL + "/validate?userName=username&otp=OTP";
        Mockito.when(restOperations.getForObject(validateURL, String.class)).thenReturn("true");

        String isOTPValid = otpRestClient.validateOTP("username", "OTP");

        verify(restOperations, times(1)).getForObject(eq(validateURL), eq(String.class));
        assertThat(isOTPValid, is("true"));
    }
}