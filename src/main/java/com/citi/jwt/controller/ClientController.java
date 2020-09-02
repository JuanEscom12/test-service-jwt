package com.citi.jwt.controller;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.citi.jwt.feign.FeignRequest;
import com.citi.jwt.feign.FeignResponse;
import com.citi.jwt.service.CitiJwtService;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping(value = "/citi/jwt")
@Slf4j
public class ClientController {

	private static final String PATH_TEST_JWT = "${app.path-citi-test}";

	private static final String PATH_RETRIEVE_PURCHASE_ORDER_PDF = "${app.path-retrieve-purchaseorder-pdf}";
	
	@Autowired
	private CitiJwtService citiJwtService; 
	
	@PostMapping(value = PATH_TEST_JWT, produces = "application/json")
	public ResponseEntity<FeignResponse> getPurchaseOrder(@RequestBody FeignRequest request) 
			throws NoSuchAlgorithmException, InvalidKeySpecException, JoseException, IOException {
		log.info(":: Controller {} ", request);
		return new ResponseEntity<>(citiJwtService.executeJweRsa(), HttpStatus.OK);
	}
	
	@PostMapping(value = "/citi/jwt/noencryption", produces = "application/json")
	public ResponseEntity<FeignResponse> getPurchaseOrderWithoutEncryption(@RequestBody FeignRequest request) 
			throws NoSuchAlgorithmException, InvalidKeySpecException, JoseException, IOException {
		log.info(":: Controller {} ", request);
		return new ResponseEntity<>(citiJwtService.executeNoEncryption(), HttpStatus.OK);
	}

	
	@GetMapping(value = PATH_RETRIEVE_PURCHASE_ORDER_PDF, produces = "application/pdf")
	public ResponseEntity<byte[]> getPurchaseOrderPdf(
			@PathVariable(name = "idPurchaseOrder") Integer idPurchaseOrder) {
		log.info(":: Get Purchase Order Status Handler {} ", idPurchaseOrder);
		
		return new ResponseEntity<>(null, HttpStatus.OK);
	}

}
