package org.openmrs.module.externalauth.filter;

import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

public class OTPRestClient {

    private RestOperations restOperations = new RestTemplate();

    public static final String OTP_URL = "http://localhost:8080/";

    public void sendOTP(String userName) {
        String url = String.format(OTP_URL + "send?userName=%s", userName);
        restOperations.getForObject(url, String.class);
    }

    public boolean validateOTP(String userName, String otp) {
        String url = String.format(OTP_URL + "validate?userName=%s&otp=%s", userName, otp);
        String response = restOperations.getForObject(url, String.class);
        return Boolean.valueOf(response);
    }
}
