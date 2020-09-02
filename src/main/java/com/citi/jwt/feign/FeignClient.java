package com.citi.jwt.feign;

import java.util.Map;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@org.springframework.cloud.openfeign.FeignClient(name = "citi-service-receiver-jwt")
public interface FeignClient {

	 /**
     * Interface method to get the greetings information from a different microservice.
     * @param langCode
     * @return
     */
    @PostMapping(value= "/mock/pdf/serialized")
    public FeignResponse getCitiMock(@RequestHeader Map<String, String> headerMap, @RequestBody FeignRequest request);
    
    @PostMapping(value= "/mock/citi/jwt/receiver/noencryption")
    public FeignResponse getCitiMockNoEncryption(@RequestHeader Map<String, String> headerMap, @RequestBody FeignRequest request);
    
	
}
