package com.mulesoft.modules.internal.utils;

public class JWE {

	private String jweHeaderB64;
	private String jweKeyB64;
	private String jweIVB64;
	private String jweEncryptedContentB64;
	private String jweAuthTagB64;
	private String jweHeaderB64JSON;
	private String jweIVB64JSON;
	private String jweEncryptedContentB64JSON;
	private String jweAuthTagB64JSON;
	private Integer parts;

	/**
	 * @return the jweHeaderB64
	 */
	public String getJweHeaderB64() {
		return jweHeaderB64;
	}

	/**
	 * @param jweHeaderB64
	 *            the jweHeaderB64 to set
	 */
	public void setJweHeaderB64(String jweHeaderB64) {
		this.jweHeaderB64 = jweHeaderB64;
	}

	/**
	 * @return the jweKeyB64
	 */
	public String getJweKeyB64() {
		return jweKeyB64;
	}

	/**
	 * @param jweKeyB64
	 *            the jweKeyB64 to set
	 */
	public void setJweKeyB64(String jweKeyB64) {
		this.jweKeyB64 = jweKeyB64;
	}

	/**
	 * @return the jweIVB64
	 */
	public String getJweIVB64() {
		return jweIVB64;
	}

	/**
	 * @param jweIVB64
	 *            the jweIVB64 to set
	 */
	public void setJweIVB64(String jweIVB64) {
		this.jweIVB64 = jweIVB64;
	}

	/**
	 * @return the jweEncryptedContentB64
	 */
	public String getJweEncryptedContentB64() {
		return jweEncryptedContentB64;
	}

	/**
	 * @param jweEncryptedContentB64
	 *            the jweEncryptedContentB64 to set
	 */
	public void setJweEncryptedContentB64(String jweEncryptedContentB64) {
		this.jweEncryptedContentB64 = jweEncryptedContentB64;
	}

	/**
	 * @return the jweAuthTagB64
	 */
	public String getJweAuthTagB64() {
		return jweAuthTagB64;
	}

	/**
	 * @param jweAuthTagB64
	 *            the jweAuthTagB64 to set
	 */
	public void setJweAuthTagB64(String jweAuthTagB64) {
		this.jweAuthTagB64 = jweAuthTagB64;
	}

	/**
	 * @return the jweHeaderB64JSON
	 */
	public String getJweHeaderB64JSON() {
		return jweHeaderB64JSON;
	}

	/**
	 * @param jweHeaderB64JSON
	 *            the jweHeaderB64JSON to set
	 */
	public void setJweHeaderB64JSON(String jweHeaderB64JSON) {
		this.jweHeaderB64JSON = jweHeaderB64JSON;
	}

	/**
	 * @return the jweIVB64JSON
	 */
	public String getJweIVB64JSON() {
		return jweIVB64JSON;
	}

	/**
	 * @param jweIVB64JSON
	 *            the jweIVB64JSON to set
	 */
	public void setJweIVB64JSON(String jweIVB64JSON) {
		this.jweIVB64JSON = jweIVB64JSON;
	}

	/**
	 * @return the jweEncryptedContentB64JSON
	 */
	public String getJweEncryptedContentB64JSON() {
		return jweEncryptedContentB64JSON;
	}

	/**
	 * @param jweEncryptedContentB64JSON
	 *            the jweEncryptedContentB64JSON to set
	 */
	public void setJweEncryptedContentB64JSON(String jweEncryptedContentB64JSON) {
		this.jweEncryptedContentB64JSON = jweEncryptedContentB64JSON;
	}

	/**
	 * @return the jweAuthTagB64JSON
	 */
	public String getJweAuthTagB64JSON() {
		return jweAuthTagB64JSON;
	}

	/**
	 * @param jweAuthTagB64JSON
	 *            the jweAuthTagB64JSON to set
	 */
	public void setJweAuthTagB64JSON(String jweAuthTagB64JSON) {
		this.jweAuthTagB64JSON = jweAuthTagB64JSON;
	}

	/**
	 * @return the parts
	 */
	public Integer getParts() {
		return parts;
	}

	/**
	 * @param parts
	 *            the parts to set
	 */
	public void setParts(Integer parts) {
		this.parts = parts;
	}

	@SuppressWarnings("static-access")
	public static JWE parseJWE(String jwe) {
		JWE token = new JWE();
		String[] jweSplitted = jwe.split("\\.");
		if (token.getParts() != 5) {
			throw new RuntimeException("JWE has " + token.getParts() + " parts.");
		}

		jweSplitted = jwe.substring(7).split("\\.");
		token.setJweHeaderB64(jweSplitted[0]);
		token.setJweKeyB64(jweSplitted[1]);
		token.setJweIVB64(jweSplitted[2]);
		token.setJweEncryptedContentB64(jweSplitted[3]);
		token.setJweAuthTagB64(jweSplitted[4]);

		org.apache.commons.codec.binary.Base64 base64 = new org.apache.commons.codec.binary.Base64();
		if (!base64.isBase64(token.getJweHeaderB64()) && !base64.isBase64(token.getJweAuthTagB64())
				&& !base64.isBase64(token.getJweIVB64()) && !base64.isBase64(token.getJweEncryptedContentB64())) {
			throw new RuntimeException("JWE does not have base64 parts.");
		}

		try {
			token.setJweAuthTagB64JSON(new String(base64.decodeBase64(token.getJweAuthTagB64())));
			token.setJweEncryptedContentB64JSON(new String(base64.decodeBase64(token.getJweEncryptedContentB64())));
			token.setJweIVB64JSON(new String(base64.decodeBase64(token.getJweIVB64())));
			token.setJweHeaderB64JSON(new String(base64.decodeBase64(token.getJweHeaderB64())));
		} catch (Exception e) {
			throw new RuntimeException("Error decoding Base64");
		}
		return token;
	}

}
