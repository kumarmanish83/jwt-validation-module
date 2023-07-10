package com.mulesoft.modules.internal.operations;

/**
 * @since 01 August 2018
 * @version 1.0.0
 * This class is used to propagate client identification to the Anypoint Platform for Analytics purposes.
 */

import static org.mule.runtime.core.api.config.MuleProperties.OBJECT_SECURITY_MANAGER;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Named;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mule.runtime.api.lifecycle.Initialisable;
import org.mule.runtime.api.lifecycle.InitialisationException;
import org.mule.runtime.api.security.Authentication;
import org.mule.runtime.api.security.Credentials;
import org.mule.runtime.api.security.DefaultMuleAuthentication;
import org.mule.runtime.api.security.SecurityException;
import org.mule.runtime.core.api.security.AbstractSecurityProvider;
import org.mule.runtime.core.api.security.DefaultMuleCredentials;
import org.mule.runtime.core.api.security.SecurityManager;
import org.mule.runtime.extension.api.annotation.param.Optional;
import org.mule.runtime.extension.api.security.AuthenticationHandler;

import com.mulesoft.modules.internal.utils.ClaimsVariables;
import com.mulesoft.modules.internal.utils.JWT;
import com.mulesoft.modules.internal.utils.TokenValidationUtils;

public class AuthenticationHeaders implements Initialisable {
	
	static final String JWT_SECURITY_PROVIDER = "jwtSecurityProvider";

	@Inject
	@Named(OBJECT_SECURITY_MANAGER)
	private SecurityManager securityManager;
	
	private static Log logger = LogFactory.getLog("JwtValidationPolicy");

	
	/**
	 * Security Manager initilization
	 */
	@Override
	public void initialise() throws InitialisationException {
		if (!isProviderPresent(JWT_SECURITY_PROVIDER)) {
			AbstractSecurityProvider provider = new AbstractSecurityProvider(JWT_SECURITY_PROVIDER) {

				@Override
				public Authentication authenticate(Authentication authentication) throws SecurityException {
					return authentication;
				}
			};

			securityManager.addProvider(provider);

			provider.initialise();
		}
	}

	/**
	 * Check if the security provider is present
	 * @param providerName
	 * @return
	 */
	private boolean isProviderPresent(String providerName) {
		return securityManager
				.getProviders()
				.stream()
				.anyMatch(provider -> provider.getName().equals(providerName));
	}
	
	/**
	 * This method creates the authentication headers for analytics purposes
	 * https://docs.mulesoft.com/mule-sdk/v/1.1/authentication-handler
	 * @param token
	 * @param clientId
	 * @param authenticationHandler
	 */
	public void createAuthHeaders(String httpAuthorization, @Optional(defaultValue = "#[attributes.headers.'client_id']") String clientId, boolean allowUnsecuredTokens, AuthenticationHandler authenticationHandler) throws Exception {
		TokenValidationUtils tokenValidation = new TokenValidationUtils();
		ClaimsVariables claimVariables = new ClaimsVariables();
		try {
			logger.debug("Validating HTTP Header");
			tokenValidation.validateAuthHeader(httpAuthorization);
			logger.debug("Parsing token");
			JWT token = JWT.parseJwt(httpAuthorization.split(" ")[1], allowUnsecuredTokens);
			if (clientId == null || clientId.equals("")) {
				String tokenClientId = "";
				if (token.getPayload().containsKey(claimVariables.getClientid())) {
					tokenClientId = (String) token.getPayload().get(claimVariables.getClientid());
				} else {
					tokenClientId = (String) token.getPayload().get(claimVariables.getCID());
				}
				
				if (tokenClientId != null && !tokenClientId.equals("")) {
					clientId = tokenClientId;
				}
			}

			if (clientId != null && !clientId.equals("")) {
				Credentials credentials = new DefaultMuleCredentials(clientId, "".toCharArray());
				Authentication authentication = new DefaultMuleAuthentication(credentials);
				Map<String, Object> properties = new HashMap<>();
				properties.put(claimVariables.getClientid(), clientId);
				List<String> providerNames = new ArrayList<>();
				providerNames.add(JWT_SECURITY_PROVIDER);
				authenticationHandler.setAuthentication(providerNames, authentication.setProperties(properties));
			}
		} catch (Exception e) {
			logger.error(e.getMessage());
			throw new RuntimeException(e.getMessage());
		}

	}
	

}
