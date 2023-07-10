package com.mulesoft.modules.internal.utils;

/**
 * @since 01 August 2018
 * @version 1.0.0
 * This class is a container for operations, every public method in this class
 * will be taken as an extension operation.
 * This class contains the variable static values being used for validating a JWT Token.
 */

public class ClaimsVariables {
	
	private final String CLIENTID = "clientId";
	private final String CID = "cid";
	private final String ISS = "iss";
	private final String ISSUER = "issuer";
	private final String AUD = "aud";
	private final String AUDIENCE = "audience";
	private final String EXP = "exp";
	private final String EXPIRY = "expiry";
	private final String EXPIRATION = "expiration";
	private final String NBF = "nbf";
	private final String SCP = "scp";
	private final String SCOPES = "scopes";
	private final String SCOPE = "scope";
	
	/**
	 * @return the clientid
	 */
	public String getClientid() {
		return CLIENTID;
	}
	/**
	 * @return the iss
	 */
	public String getIss() {
		return ISS;
	}
	/**
	 * @return the issuer
	 */
	public String getIssuer() {
		return ISSUER;
	}
	/**
	 * @return the aud
	 */
	public String getAud() {
		return AUD;
	}
	/**
	 * @return the audience
	 */
	public String getAudience() {
		return AUDIENCE;
	}
	/**
	 * @return the exp
	 */
	public String getExp() {
		return EXP;
	}
	/**
	 * @return the expiry
	 */
	public String getExpiry() {
		return EXPIRY;
	}
	/**
	 * @return the expiration
	 */
	public String getExpiration() {
		return EXPIRATION;
	}
	/**
	 * @return the nbf
	 */
	public String getNbf() {
		return NBF;
	}
	/**
	 * @return the scp
	 */
	public String getScp() {
		return SCP;
	}
	/**
	 * @return the scopes
	 */
	public String getScopes() {
		return SCOPES;
	}
	/**
	 * @return the scope
	 */
	public String getScope() {
		return SCOPE;
	}
	/**
	 * @return the cID
	 */
	public String getCID() {
		return CID;
	}

}
