package org.openmrs.module.externalauth.filter;

import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

public class OTPRestClient {

    private RestOperations restOperations = new RestTemplate();

    public static final String OTP_URL = "http://localhost:8058/";

    public void sendOTP(String userName) {
        String url = String.format(OTP_URL + "send?userName=%s", userName);
        restOperations.getForObject(url, String.class);
    }

    public String validateOTP(String userName, String otp) {
        String url = String.format(OTP_URL + "validate?userName=%s&otp=%s", userName, otp);
        return restOperations.getForObject(url, String.class);
    }
}
