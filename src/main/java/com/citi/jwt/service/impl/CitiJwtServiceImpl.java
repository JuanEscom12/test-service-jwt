package com.citi.jwt.service.impl;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

import com.citi.jwt.feign.FeignClient;
import com.citi.jwt.feign.FeignRequest;
import com.citi.jwt.feign.FeignResponse;
import com.citi.jwt.service.CitiJwtService;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class CitiJwtServiceImpl implements CitiJwtService {

	@SuppressWarnings("deprecation")
	private static final AlgorithmConstraints CONTENT_ENCRYPTION_ALGORITHM_CONSTRAINTS = new AlgorithmConstraints(
			ConstraintType.WHITELIST, ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
	 
	@SuppressWarnings("deprecation")
	private static final AlgorithmConstraints KEY_ENCRYPTION_ALGORITHM_CONSTRAINTS = new AlgorithmConstraints(
			ConstraintType.WHITELIST, KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);

	private static final String PATH_KEY_FILE = "jwe_key_file";

	private static final String PATH_JWS_KEY_FILE = "jws_key_file";
	
	private static final String PRIVATE_EXTENSION = ".key";
	
	private static final String PUBLIC_EXTENSION = ".pub";
	
	private static final int LENGTH_KEY = 2048;

	@Autowired
	private FeignClient feignClient;
		
	@Autowired
	private ResourceLoader resourceLoader;

//	@Autowired
//	private RestTemplate restTemplate;
	
	@Override
	public FeignResponse executeJweRsa() 
			throws NoSuchAlgorithmException, InvalidKeySpecException, JoseException, IOException {
		log.info("********************** SERVICE ***************************");
		long millisStar = Calendar.getInstance().getTimeInMillis();
//		Map<String, Object> map = new HashMap<String, Object>();
//		FeignRequest reque = new FeignRequest();
//		reque.setParameter("sss");
//		FeignResponse re = restTemplate.postForObject("http://citi-service-receiver-jwt/mock/citi/jwt/receiver/noencryption", reque, FeignResponse.class, map);
//		log.info("****************************** RESULT {} ", re);
		
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(
				new X509EncodedKeySpec(getKeyFromFile(PATH_KEY_FILE, PUBLIC_EXTENSION)));
		JsonWebEncryption jwe = new JsonWebEncryption();
		jwe.setPayload(getStringJWs());		
		jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
		jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
		jwe.setKey(publicKey);
	    long iat = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
	    jwe.getHeaders().setObjectHeaderValue("iat", iat);
		final String jweCompact = jwe.getCompactSerialization();
		//log.info(":::::::::::::::::: JWE Compact Client {} ", jweCompact);
		final Map<String, String> headerMap = new HashMap<>();
		headerMap.put("Content-Type", "application/json");
		headerMap.put("Authorization", jweCompact);
		headerMap.put("channelID", jweCompact);
		FeignRequest request = new FeignRequest();
		request.setParameter(jweCompact);

		FeignResponse response = feignClient.getCitiMock(headerMap, request);
		//log.info("::::::::::: Result {} ", response);
		//////////////////////////////////////////////// DECODED ////////////////////////////////////////////////////////////
	    RSAPrivateKey privateKey = (RSAPrivateKey)keyFactory.generatePrivate(
	    		new PKCS8EncodedKeySpec(getKeyFromFile(PATH_KEY_FILE, PRIVATE_EXTENSION)));  		
	    JsonWebEncryption jweDecod = new JsonWebEncryption();
	    jweDecod.setAlgorithmConstraints(KEY_ENCRYPTION_ALGORITHM_CONSTRAINTS);
	    jweDecod.setContentEncryptionAlgorithmConstraints(CONTENT_ENCRYPTION_ALGORITHM_CONSTRAINTS);
	    jweDecod.setKey(privateKey);
	    jweDecod.setCompactSerialization(response.getParameter());
	    iat = jweDecod.getHeaders().getLongHeaderValue("iat");
	    log.info(":::::::::::::::: Claim iat private :" + iat);
	    String payload = jweDecod.getPayload();
	    payload = getStringJwsDeserealized(payload);
	    log.info(":::::::::::::::: Payload Private {} ");
	    log.info("****** Tiempo total del proceso: {} ", Calendar.getInstance().getTimeInMillis() - millisStar);
	    return response;
	}
			
	/**
	 * Crea las llaves para el cifrado de JWE (Solo se ejecuta una vez y las llaves se guardan en archivos).
	 * 
	 */
	public void createKeyFiles() throws IOException, NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(LENGTH_KEY);
		KeyPair kp = kpg.generateKeyPair();
		Key pub = kp.getPublic();
		Key pvt = kp.getPrivate();
		
		FileOutputStream out = new FileOutputStream(PATH_KEY_FILE + PRIVATE_EXTENSION);
		out.write(pvt.getEncoded());
		out.close();

		out = new FileOutputStream(PATH_KEY_FILE + PUBLIC_EXTENSION);
		out.write(pub.getEncoded());
		out.close();
	}
	
	/**
	 * Crea las llaves para la firma de JWS (Solo se ejecuta una vez y las llaves se guardan en archivos).
	 * 
	 */
	public void createSigningKeys() throws NoSuchAlgorithmException, IOException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
	    generator.initialize(2048, new SecureRandom());
	    KeyPair pair = generator.generateKeyPair();
	    Key pub = pair.getPublic();
		Key pvt = pair.getPrivate();
	    
		FileOutputStream out = new FileOutputStream(PATH_JWS_KEY_FILE + PRIVATE_EXTENSION);
		out.write(pvt.getEncoded());
		out.close();

		out = new FileOutputStream(PATH_JWS_KEY_FILE + PUBLIC_EXTENSION);
		out.write(pub.getEncoded());
		out.close();
	}
	
	private byte[] getKeyFromFile(String pathDirectory, String keyExtension) throws IOException {
		Resource resource = resourceLoader.getResource("classpath:" + pathDirectory + keyExtension);		
		log.info("************************* Resource-length {} ", resource.getInputStream().readAllBytes().length);
	    return resource.getInputStream().readAllBytes();
	}
	
	public String getStringJWs() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		// The content that will be signed
		String examplePayload = "Request: This is some text that is to be signed.";

		// Create a new JsonWebSignature
		JsonWebSignature jws = new JsonWebSignature();

		// Set the payload, or signed content, on the JWS object
		jws.setPayload(examplePayload);

		// Set the signature algorithm on the JWS that will integrity protect the
		// payload
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

		// Set the signing key on the JWS
		// Note that your application will need to determine where/how to get the key
		// and here we just use an example from the JWS spec
//		PrivateKey privateKey = ExampleEcKeysFromJws.PRIVATE_256;
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPrivateKey privateKey = (RSAPrivateKey)keyFactory.generatePrivate(
	    		new PKCS8EncodedKeySpec(getKeyFromFile(PATH_JWS_KEY_FILE, PRIVATE_EXTENSION)));
		jws.setKey(privateKey);

		// Sign the JWS and produce the compact serialization or complete JWS
		// representation, which
		// is a string consisting of three dot ('.') separated base64url-encoded
		// parts in the form Header.Payload.Signature
		String jwsCompactSerialization = null;
		try {
			jwsCompactSerialization = jws.getCompactSerialization();
			// Do something useful with your JWS
			//log.info(":::::::::::::::::: Serialization JWS {} ", jwsCompactSerialization);
		} catch (JoseException e) {
			e.printStackTrace();
		}
		return jwsCompactSerialization;
	}

	private String getStringJwsDeserealized(String compactSerialization) 
			throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		// Create a new JsonWebSignature
		JsonWebSignature jwsSignature = new JsonWebSignature();
		
		// Set the algorithm constraints based on what is agreed upon or expected from
		// the sender
		jwsSignature.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT,
				AlgorithmIdentifiers.RSA_USING_SHA256));

		// Set the compact serialization on the JWS
		try {
			jwsSignature.setCompactSerialization(compactSerialization);
		} catch (JoseException e) {
			e.printStackTrace();
		}
		
		// Set the verification key
		// Note that your application will need to determine where/how to get the key
		// Here we use an example from the JWS spec
//		PublicKey publicKey = ExampleEcKeysFromJws.PUBLIC_256;
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(
				new X509EncodedKeySpec(getKeyFromFile(PATH_JWS_KEY_FILE, PUBLIC_EXTENSION)));
		jwsSignature.setKey(publicKey);

		// Check the signature
		String payload = null;
		try {
			boolean signatureVerified = jwsSignature.verifySignature();
			// Do something useful with the result of signature verification
			log.info("::::::::::: JWS Signature is valid: {} ", signatureVerified);

			// Get the payload, or signed content, from the JWS
			payload = jwsSignature.getPayload();

			// Do something useful with the content
			//log.info(":::::::::::: JWS payload: {} ", payload);
		} catch (JoseException e) {
			e.printStackTrace();
		}
		return payload;
	}

	
	@Override
	public void executeJws() {

		log.info("::::::::::::: JWS implementation ");
		//
		// An example of signing using JSON Web Signature (JWS)
		//

		// The content that will be signed
		String examplePayload = "This is some text that is to be signed.";

		// Create a new JsonWebSignature
		JsonWebSignature jws = new JsonWebSignature();

		// Set the payload, or signed content, on the JWS object
		jws.setPayload(examplePayload);

		// Set the signature algorithm on the JWS that will integrity protect the
		// payload
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

		// Set the signing key on the JWS
		// Note that your application will need to determine where/how to get the key
		// and here we just use an example from the JWS spec
		PrivateKey privateKey = ExampleEcKeysFromJws.PRIVATE_256;
		jws.setKey(privateKey);

		// Sign the JWS and produce the compact serialization or complete JWS
		// representation, which
		// is a string consisting of three dot ('.') separated base64url-encoded
		// parts in the form Header.Payload.Signature
		String jwsCompactSerialization = null;
		try {
			jwsCompactSerialization = jws.getCompactSerialization();
			// Do something useful with your JWS
			//log.info(":::::::::::::::::: Serialization {} ", jwsCompactSerialization);
		} catch (JoseException e) {
			e.printStackTrace();
		}

		//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		// Create a new JsonWebSignature
		JsonWebSignature jwsSignature = new JsonWebSignature();

		// Set the algorithm constraints based on what is agreed upon or expected from
		// the sender
		jwsSignature.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT,
				AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256));

		// Set the compact serialization on the JWS
		try {
			jwsSignature.setCompactSerialization(jwsCompactSerialization);
		} catch (JoseException e) {
			e.printStackTrace();
		}

		// Set the verification key
		// Note that your application will need to determine where/how to get the key
		// Here we use an example from the JWS spec
		PublicKey publicKey = ExampleEcKeysFromJws.PUBLIC_256;
		jwsSignature.setKey(publicKey);

		// Check the signature
		boolean signatureVerified;
		try {
			signatureVerified = jwsSignature.verifySignature();

			// Do something useful with the result of signature verification
			log.info("::::::::::: JWS Signature is valid: {} ", signatureVerified);

			// Get the payload, or signed content, from the JWS
			String payload = jwsSignature.getPayload();

			// Do something useful with the content
			//log.info(":::::::::::: JWS payload: {} ", payload);
		} catch (JoseException e) {
			e.printStackTrace();
		}

	}

	@Override
	public void executeJwe() {
		// An example showing the use of JSON Web Encryption (JWE) to encrypt and then
		// decrypt some content
		// using a symmetric key and direct encryption.
		//

		// The content to be encrypted
		String message = "Well, as of this moment, they're on DOUBLE SECRET PROBATION!";

		// The shared secret or shared symmetric key represented as a octet sequence
		// JSON Web Key (JWK)
		String jwkJson = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
		JsonWebKey jwk = null;
		try {
			jwk = JsonWebKey.Factory.newJwk(jwkJson);
		} catch (JoseException e) {
			e.printStackTrace();
		}

		// Create a new Json Web Encryption object
		JsonWebEncryption senderJwe = new JsonWebEncryption();

		// The plaintext of the JWE is the message that we want to encrypt.
		senderJwe.setPlaintext(message);

		// Set the "alg" header, which indicates the key management mode for this JWE.
		// In this example we are using the direct key management mode, which means
		// the given key will be used directly as the content encryption key.
		senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);

		// Set the "enc" header, which indicates the content encryption algorithm to be
		// used.
		// This example is using AES_128_CBC_HMAC_SHA_256 which is a composition of AES
		// CBC
		// and HMAC SHA2 that provides authenticated encryption.
		senderJwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);

		// Set the key on the JWE. In this case, using direct mode, the key will used
		// directly as
		// the content encryption key. AES_128_CBC_HMAC_SHA_256, which is being used to
		// encrypt the
		// content requires a 256 bit key.
		senderJwe.setKey(jwk.getKey());

		// Produce the JWE compact serialization, which is where the actual encryption
		// is done.
		// The JWE compact serialization consists of five base64url encoded parts
		// combined with a dot ('.') character in the general format of
		// <header>.<encrypted key>.<initialization vector>.<ciphertext>.<authentication
		// tag>
		// Direct encryption doesn't use an encrypted key so that field will be an empty
		// string
		// in this case.
		String compactSerialization = null;
		try {
			compactSerialization = senderJwe.getCompactSerialization();
		} catch (JoseException e) {
			e.printStackTrace();
		}

//		jwe.setKeyIdHeaderValue(keyId);
//      jwe.setContentTypeHeaderValue(contentType);

		// Do something with the JWE. Like send it to some other party over the clouds
		// and through the interwebs.
		//log.info(":::::::::::::: JWE compact serialization: {} ", compactSerialization);

		///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		// That other party, the receiver, can then use JsonWebEncryption to decrypt the
		// message.
		JsonWebEncryption receiverJwe = new JsonWebEncryption();

		// Set the algorithm constraints based on what is agreed upon or expected from
		// the sender
		AlgorithmConstraints algConstraints = new AlgorithmConstraints(ConstraintType.PERMIT,
				KeyManagementAlgorithmIdentifiers.DIRECT);
		receiverJwe.setAlgorithmConstraints(algConstraints);
		AlgorithmConstraints encConstraints = new AlgorithmConstraints(ConstraintType.PERMIT,
				ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
		receiverJwe.setContentEncryptionAlgorithmConstraints(encConstraints);

		// Set the compact serialization on new Json Web Encryption object
		try {
			receiverJwe.setCompactSerialization(compactSerialization);
		} catch (JoseException e) {
			e.printStackTrace();
		}

		// Symmetric encryption, like we are doing here, requires that both parties have
		// the same key.
		// The key will have had to have been securely exchanged out-of-band somehow.
		receiverJwe.setKey(jwk.getKey());

		// Get the message that was encrypted in the JWE. This step performs the actual
		// decryption steps.
		String plaintext = null;
		try {
			plaintext = receiverJwe.getPlaintextString();
		} catch (JoseException e) {
			e.printStackTrace();
		}

		// And do whatever you need to do with the clear text message.
		//log.info("::::::::::::::::: Plaintext: {} ", plaintext);
	}

	@Override
	public FeignResponse executeNoEncryption() {
		final Map<String, String> headerMap = new HashMap<>();
		headerMap.put("Content-Type", "application/json");
		final FeignRequest request = new FeignRequest();
		return feignClient.getCitiMockNoEncryption(headerMap, request);
	}
	
}
