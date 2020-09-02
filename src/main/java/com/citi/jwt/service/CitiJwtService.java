package com.citi.jwt.service;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.jose4j.lang.JoseException;

import com.citi.jwt.feign.FeignResponse;

public interface CitiJwtService {
	
	void executeJws();
	
	void executeJwe();
	
	FeignResponse executeJweRsa() throws NoSuchAlgorithmException, InvalidKeySpecException, JoseException, IOException;
		
	FeignResponse executeNoEncryption();
	
	void createKeyFiles() throws IOException, NoSuchAlgorithmException;
	
	void createSigningKeys() throws NoSuchAlgorithmException, IOException;
	
	String getStringJWs() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException;
}
