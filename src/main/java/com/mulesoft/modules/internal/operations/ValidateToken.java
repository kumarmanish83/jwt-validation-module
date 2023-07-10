package com.mulesoft.modules.internal.operations;

/**
 * @version 1.0.0
 * This class is a container for operations, every public method in this class
 * will be taken as an extension operation.
 * This class validates a JWT token against the claims provided by the user.
 */

import com.mulesoft.modules.internal.utils.ClaimsVariables;
import com.mulesoft.modules.internal.utils.JWT;
import com.mulesoft.modules.internal.utils.OutputEntityResolver;
import com.mulesoft.modules.internal.utils.TokenValidationUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mule.runtime.core.api.el.ExpressionManager;
import org.mule.runtime.extension.api.annotation.metadata.OutputResolver;
import org.mule.runtime.extension.api.annotation.param.MediaType;
import org.mule.runtime.extension.api.annotation.param.Optional;

import javax.inject.Inject;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ValidateToken {

	@Inject
	ExpressionManager em;

	private static Log logger = LogFactory.getLog("JwtValidationPolicy");

	/**
	 * Module Operation to validate token
	 *
	 * @param httpAuthorization
	 *            Bearer Token
	 * @param certificate
	 *            Certificates used to sign the token
	 * @param issuer
	 *            Issuers of the token
	 * @param audience
	 *            Audience of the token
	 * @param expirationTolerance
	 *            Integer
	 * @param checkExpiration
	 *            Boolean
	 * @param checkNotBefore
	 *            Boolean
	 * @param allowUnsecuredTokens
	 *            Boolean
	 * @param scopes
	 *            Scopes to be validated against the token
	 * @param clientId
	 *            Client calling to validate the token
	 * @param authenticationHandler
	 *            This allows the client information to be passed downstream for
	 *            identification purposes
	 * @return true/false
	 */
	public boolean validateToken(String httpAuthorization, String certificate, String issuer, String audience,
			Integer expirationTolerance, boolean checkExpiration, boolean checkNotBefore, boolean allowUnsecuredTokens,
			@Optional List<String> scopes, @Optional Map<String, String> claims) {
		ClaimsVariables claimVariables = new ClaimsVariables();
		TokenValidationUtils tokenValidation = new TokenValidationUtils();
		try {
			logger.debug("Validating HTTP Header");
			tokenValidation.validateAuthHeader(httpAuthorization);
			logger.debug("Parsing token");
			JWT token = JWT.parseJwt(httpAuthorization.split(" ")[1], allowUnsecuredTokens);
			tokenValidation.validateUnsecuredToken(token, allowUnsecuredTokens);
			if (!allowUnsecuredTokens) {
				logger.debug("Validating signature");
				tokenValidation.validateSignature(token, certificate);
			}
			if (claims != null && !claims.isEmpty()) {
				logger.debug("Validation custom claims");
				tokenValidation.validateCustomClaims(token, claims);
			}
			if (issuer != null && !issuer.isEmpty()) {
				logger.debug("Validating issuer");
				tokenValidation.validateIssuer(token, issuer, claimVariables);
			}
			if (audience != null && !audience.isEmpty()) {
				logger.debug("Validating audience");
				tokenValidation.validateAudience(token, audience, claimVariables);
			}

			logger.debug("Validating checkExpiration");
			tokenValidation.validateExpiration(token, checkExpiration, expirationTolerance, claimVariables);
			logger.debug("Validating checkNotBefore");
			tokenValidation.validateNotBefore(token, checkNotBefore, claimVariables);
			if (scopes.size() != 0) {
				logger.debug("Validating scope {}");
				tokenValidation.validateScope(token, scopes, claimVariables);
			}
			return true;
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return false;
		}
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@OutputResolver(output = OutputEntityResolver.class)
	public Map<String, Object> inspectToken(String httpAuthorization, String certificate, String issuer,
			String audience, Integer expirationTolerance, boolean checkExpiration, boolean checkNotBefore,
			boolean allowUnsecuredTokens, @Optional List<String> scopes,
			@Optional(defaultValue = "#[attributes.headers.'client_id']") String clientId,
			@Optional String identityProvider, @Optional Map<String, String> claims) {
		ClaimsVariables claimVariables = new ClaimsVariables();
		TokenValidationUtils tokenValidation = new TokenValidationUtils();
		try {
			logger.debug("Validating HTTP Header");
			tokenValidation.validateAuthHeader(httpAuthorization);
			logger.debug("Parsing token");
			JWT token = JWT.parseJwt(httpAuthorization.split(" ")[1], allowUnsecuredTokens);
			tokenValidation.validateUnsecuredToken(token, allowUnsecuredTokens);
			if (!allowUnsecuredTokens) {
				logger.debug("Validating signature");
				tokenValidation.validateSignature(token, certificate);
			}
			if (claims != null && !claims.isEmpty()) {
				logger.debug("Validation custom claims");
				tokenValidation.validateCustomClaims(token, claims);
			}
			if (issuer != null && !issuer.isEmpty()) {
				logger.debug("Validating issuer");
				tokenValidation.validateIssuer(token, issuer, claimVariables);
			}
			if (audience != null && !audience.isEmpty()) {
				logger.debug("Validating audience");
				tokenValidation.validateAudience(token, audience, claimVariables);
			}
			logger.debug("Validating checkExpiration");
			tokenValidation.validateExpiration(token, checkExpiration, expirationTolerance, claimVariables);
			logger.debug("Validating checkNotBefore");
			tokenValidation.validateNotBefore(token, checkNotBefore, claimVariables);
			if (scopes.size() != 0) {
				tokenValidation.validateScope(token, scopes, claimVariables);
			}
			token.getPayload().put("isValid", true);
			return token.getPayload();
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return new HashMap();
		}
	}
	
	@MediaType(value = "plain/text")
	public String getIssuer(String httpAuthorization,boolean allowUnsecuredTokens) {
	 		String issuer = "";
	 		ClaimsVariables claimVariables = new ClaimsVariables();
	 		TokenValidationUtils tokenValidation = new TokenValidationUtils();
	 		try {
	 			logger.debug("Started getIssuer function");
	 			//tokenValidation.validateAuthHeader(httpAuthorization);
	 			logger.debug("Parsing token");
	 			JWT token = JWT.parseJwt(httpAuthorization.split(" ")[1], allowUnsecuredTokens);
				
	 			issuer = tokenValidation.retrieveIssuer(token, claimVariables);
				
	 			return issuer;
	 		} catch (Exception e) {
	 			logger.error(e.getMessage(), e);
	 			return issuer;
	 		}
	 	}
	 

}
