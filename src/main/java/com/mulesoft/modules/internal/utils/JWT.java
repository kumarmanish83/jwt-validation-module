package com.mulesoft.modules.internal.utils;

/**
 * @since 01 August 2018
 * @version 1.0.0.
 * This class contains the structure of a JWT Token and the respective getters and setters.
 */

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.codehaus.jackson.map.ObjectMapper;

public class JWT {
	
	private String headerBase64;
	private String headerJson;
	private Map<String, Object> header;
	private String payloadBase64;
	private String payloadJson;
	private Map<String, Object> payload;
	private String signatureBase64;
	private byte[] signature;
	private Integer parts;
	Boolean validSignature;

	/**
	 * @return
	 */
	public String getAlgorithm() {
		return ((String) getHeader().get("alg"));
	}

	/**
	 * @return
	 */
	boolean isHMAC() {
		return getAlgorithm().startsWith("HS");
	}

	/**
	 * @return
	 */
	boolean isRSA() {
		return getAlgorithm().startsWith("RS");
	}

	/**
	 * @return
	 */
	boolean isECDSA() {
		return getAlgorithm().startsWith("HS");
	}

	/**
	 * @return
	 */
	public boolean isUnsecure() {
		return getAlgorithm().equals("none");
	}

	/**
	 * @return
	 */
	public Map<String, Object> getHeader() {
		return header;
	}

	/**
	 * @return
	 */
	public Map<String, Object> getPayload() {
		return payload;
	}

	/**
	 * @return
	 */
	public Boolean getValidSignature() {
		return validSignature;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		return ToStringBuilder.reflectionToString(this);
	}

	/**
	 * @return
	 */
	public Integer getParts() {
		return parts;
	}

	/**
	 * @param parts
	 */
	public void setParts(Integer parts) {
		this.parts = parts;
	}

	/**
	 * @return the headerBase64
	 */
	public String getHeaderBase64() {
		return headerBase64;
	}

	/**
	 * @param headerBase64 the headerBase64 to set
	 */
	public void setHeaderBase64(String headerBase64) {
		this.headerBase64 = headerBase64;
	}

	/**
	 * @return the payloadBase64
	 */
	public String getPayloadBase64() {
		return payloadBase64;
	}

	/**
	 * @param payloadBase64 the payloadBase64 to set
	 */
	public void setPayloadBase64(String payloadBase64) {
		this.payloadBase64 = payloadBase64;
	}

	/**
	 * @return the signatureBase64
	 */
	public String getSignatureBase64() {
		return signatureBase64;
	}

	/**
	 * @param signatureBase64 the signatureBase64 to set
	 */
	public void setSignatureBase64(String signatureBase64) {
		this.signatureBase64 = signatureBase64;
	}

	/**
	 * @return the headerJson
	 */
	public String getHeaderJson() {
		return headerJson;
	}

	/**
	 * @param headerJson the headerJson to set
	 */
	public void setHeaderJson(String headerJson) {
		this.headerJson = headerJson;
	}

	/**
	 * @return the payloadJson
	 */
	public String getPayloadJson() {
		return payloadJson;
	}

	/**
	 * @param payloadJson the payloadJson to set
	 */
	public void setPayloadJson(String payloadJson) {
		this.payloadJson = payloadJson;
	}

	/**
	 * @return the signature
	 */
	public byte[] getSignature() {
		return signature;
	}

	/**
	 * @param signature the signature to set
	 */
	public void setSignature(byte[] signature) {
		this.signature = signature;
	}

	/**
	 * @param header the header to set
	 */
	public void setHeader(Map<String, Object> header) {
		this.header = header;
	}

	/**
	 * @param payload the payload to set
	 */
	public void setPayload(Map<String, Object> payload) {
		this.payload = payload;
	}
	
	/**
	 * Parse the incoming JWT token xxxx.yyyy.zzzz and create the three parts: Header, Payload and Signature
	 * @param jwt
	 * @param allowUnsecuredTokens
	 * @return
	 */
	@SuppressWarnings("static-access")
	public static JWT parseJwt(String jwt, Boolean allowUnsecuredTokens) {
		JWT token = new JWT();
		String[] jwtSplitted = jwt.split("\\.");
		token.setParts(jwtSplitted.length);
		if (!allowUnsecuredTokens && token.getParts() != 3) {
			throw new RuntimeException("JWT has " + token.getParts() + " parts.");
		}
		if (allowUnsecuredTokens && (token.getParts() < 2 || token.getParts() > 3)) {
			throw new RuntimeException("JWT has " + token.getParts() + " parts.");
		}
		token.setHeaderBase64(jwtSplitted[0]);
		token.setPayloadBase64(jwtSplitted[1]);
		if (token.getParts().equals(3)) {
			token.setSignatureBase64(jwtSplitted[2]);
		}
		org.apache.commons.codec.binary.Base64 base64 = new org.apache.commons.codec.binary.Base64();
		try {
			token.setHeaderJson(new String(base64.decodeBase64(token.getHeaderBase64())));
			token.setPayloadJson(new String(base64.decodeBase64(token.getPayloadBase64())));
			if (token.getParts().equals(3)) {
				token.setSignature(base64.decodeBase64(token.getSignatureBase64()));
			}
		} catch (Exception e) {
			throw new RuntimeException("Error decoding Base64");
		}
		try {
			token.setHeader(parseJson(token.getHeaderJson()));
			token.setPayload(parseJson(token.getPayloadJson()));
		} catch (Exception e) {
			throw new RuntimeException("Error parsing JSON");
		}
		if (token.getAlgorithm() == null || token.getAlgorithm().length() == 0) {
			throw new RuntimeException("JWT header does not contain 'alg' attribute");
		}
		return token;
	}

	// JSON Parser
	@SuppressWarnings("unchecked")
	private static Map<String, Object> parseJson(String json) throws Exception {
		return new ObjectMapper().readValue(json.getBytes(), HashMap.class);
	}

}
