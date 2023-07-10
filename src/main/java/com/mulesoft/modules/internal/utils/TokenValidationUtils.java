package com.mulesoft.modules.internal.utils;

/**
 * @version 1.0.0
 * Utility methods class.
 * This class contains the utility methods used to validate various claims as part of the JWT Token.
 * @since 01 August 2018
 */


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;

public class TokenValidationUtils {
    Logger logger = LoggerFactory.getLogger(TokenValidationUtils.class);
    final static Map<String, String> algorithmMap;

    /**
     * HashMap containing all algorithms that are supported
     */
    static {
        algorithmMap = new HashMap<String, String>();
        algorithmMap.put("HS256", "HmacSHA256");
        algorithmMap.put("HS384", "HmacSHA384");
        algorithmMap.put("HS512", "HmacSHA512");
        algorithmMap.put("RS256", "SHA256withRSA");
        algorithmMap.put("RS384", "SHA384withRSA");
        algorithmMap.put("RS512", "SHA512withRSA");
        algorithmMap.put("ES256", "SHA256withECDSA");
        algorithmMap.put("ES384", "SHA384withECDSA");
        algorithmMap.put("ES512", "SHA512withECDSA");
    }

    /**
     * Validate the token is in correct format
     *
     * @param authHeader
     */
    public void validateAuthHeader(String authHeader) {
        if (authHeader == null || authHeader.length() == 0) {
            throw new RuntimeException("Missing Authorization header");
        } else if (!authHeader.toLowerCase().startsWith("bearer ")) {
            throw new RuntimeException("Malformed Authorization header. No Bearer scheme");
        } else if (authHeader.length() <= 7) {
            throw new RuntimeException("Malformed Authorization header. No token");
        }
    }

    /**
     * Validate the token against any of the generated certificates. This is done
     * against any number of certs available
     *
     * @param token
     * @param certificate
     * @throws Runtime Exception
     */
    public void validateSignature(JWT token, String certificate) {
        //certificate = certificate.replace("[", " ");
       // certificate = certificate.replace("]", " ");
        String[] temp = certificate.split(",");
        boolean result = false;
        for (int i = 0; i < temp.length; i++) {
            String cert = temp[i].trim();
            //cert = "-----BEGIN CERTIFICATE-----\n" + cert + "\n-----END CERTIFICATE-----";
            if (!token.isUnsecure()) {
                if (token.isHMAC()) {
                    result = validateSymmetricTokenSignature(token, cert);
                } else if (token.isRSA() || token.isECDSA()) {
                    result = (validateAsymmetricTokenSignature(token, cert)
                            || validateAsymmetricTokenSignatureEN(token, cert));
                }
            }
            if (result) {
                break;
            }
        }

        if (!result) {
            throw new RuntimeException("Token failed certificate validation.");
        }
    }

    /**
     * Method to validate Asymmetric tokens
     *
     * @param token
     * @param certificate
     * @return true/false
     */
    private static boolean validateAsymmetricTokenSignature(JWT token, String certificate) {
        String javaAlgorithm = algorithmMap.get(token.getAlgorithm());
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate publicCertificate = (X509Certificate) certFactory
                    .generateCertificate(new ByteArrayInputStream(certificate.getBytes()));
            Signature publicSignature = Signature.getInstance(javaAlgorithm);
            publicSignature.initVerify(publicCertificate);
            publicSignature.update((token.getHeaderBase64() + '.' + token.getPayloadBase64()).getBytes());
            org.apache.commons.codec.binary.Base64 base64 = new org.apache.commons.codec.binary.Base64(true);
            byte[] signatureBytes = base64.decode(token.getSignatureBase64().getBytes("UTF-8"));
            publicSignature.verify(signatureBytes);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Method to validate Asymmetric tokens which are created using the modulus and
     * exponenet calculation
     *
     * @param token
     * @param certificate
     * @return true/false
     */
    public boolean validateAsymmetricTokenSignatureEN(JWT token, String certificate) {
        try {
            byte[] pk = org.apache.commons.codec.binary.Base64.decodeBase64(certificate);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pk);
            KeyFactory keyFactory = null;
            if (token.isRSA()) {
                keyFactory = KeyFactory.getInstance("RSA");
            } else if (token.isECDSA()) {
                keyFactory = KeyFactory.getInstance("ECDSA");
            }
            PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
            String javaAlgorithm = algorithmMap.get(token.getAlgorithm());
            Signature signature = Signature.getInstance(javaAlgorithm);
            signature.initVerify(publicKey);
            signature.update((token.getHeaderBase64() + '.' + token.getPayloadBase64()).getBytes());
            org.apache.commons.codec.binary.Base64 base64 = new org.apache.commons.codec.binary.Base64(true);
            byte[] signatureBytes = base64.decode(token.getSignatureBase64().getBytes("UTF-8"));
            token.validSignature = signature.verify(signatureBytes);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Method to validate Symmetric tokens Supported algorithms: HmacSHA256,
     * HmacSHA384, HmacSHA512
     *
     * @param token
     * @param certificate
     * @return true/false
     */
    public boolean validateSymmetricTokenSignature(JWT token, String certificate) {
		try {
			String javaAlgorithm = algorithmMap.get(token.getAlgorithm());
			if (javaAlgorithm == null) {
				throw new RuntimeException(
						"JWT header 'alg' key size  with value '" + token.getAlgorithm() + "' is not supported.");
			}
			Mac macAlgorithm = Mac.getInstance(javaAlgorithm);
			SecretKeySpec secret_key = new SecretKeySpec(certificate.getBytes(),
					algorithmMap.get(token.getAlgorithm()));
			macAlgorithm.init(secret_key);
			byte[] signature = macAlgorithm
					.doFinal((token.getHeaderBase64() + '.' + token.getPayloadBase64()).getBytes());
			token.validSignature = Arrays.equals(signature, token.getSignature());
			if (token.validSignature) {
				return true;
			} else {
				throw new RuntimeException("Error validating token signature");
			}
		} catch (Exception e) {
			throw new RuntimeException("Error validating token signature");
		}
	}

    /**
     * Validate the issuer of the token
     *
     * @param token
     * @param issuer
     * @throws Runtime Exception
     */
    public void validateIssuer(JWT token, String issuer, ClaimsVariables claimVariables) {
        if (issuer != null && issuer.length() > 0) {
            String iss = "";
            if (token.getPayload().containsKey(claimVariables.getIss())) {
                iss = (String) token.getPayload().get(claimVariables.getIss());
            } else {
                iss = (String) token.getPayload().get(claimVariables.getIssuer());
            }

            if (iss == null) {
                throw new RuntimeException("JWT payload does not contain 'iss/issuer' claim");
            }
            if (!iss.equals(issuer)) {
                throw new RuntimeException("'iss/issuer' claim with value '" + iss + "' differs from required issuer");
            }
        }
    }

    /**
     * Validate the audience of the token
     *
     * @param token
     * @param audience
     * @throws Runtime Exception
     */
    public void validateAudience(JWT token, String audience, ClaimsVariables claimVariables) {
        logger.debug("User Audience {}", audience);
        boolean result = false;
        if (audience != null && audience.trim().length() > 0) {

            List<String> tokenAudiences = new ArrayList<>();
            if (token.getPayload().containsKey(claimVariables.getAud())) {
                tokenAudiences = resolveAsList(token.getPayload().get(claimVariables.getAud()));
            } else {
                tokenAudiences = resolveAsList(token.getPayload().get(claimVariables.getAudience()));
            }
            if (tokenAudiences.isEmpty()) {
                throw new RuntimeException("JWT payload does not contain 'aud/audience' claim.");
            }
            List<String> userAudiences = resolveAsList(audience);
            logger.debug("User Audiences as List {}", userAudiences.toString());
            result = validateClaimsAsList(userAudiences, result, tokenAudiences);
            if (!result) {
                throw new RuntimeException(
                        "'aud/audience' claim with value '" + tokenAudiences.toString() + "' differs from required audience.");
            }
        }
    }

    /**
     * Validate the expiration of the token
     *
     * @param token
     * @param checkExpiration
     * @param expirationTolerance
     * @throws Runtime Exception
     */
    public void validateExpiration(JWT token, Boolean checkExpiration, Integer expirationTolerance,
                                   ClaimsVariables claimVariables) {
        if (checkExpiration != null && checkExpiration) {
            Integer tokenExp = 0;
            if (token.getPayload().containsKey(claimVariables.getExp())) {
                tokenExp = (Integer) token.getPayload().get(claimVariables.getExp());
            } else if (token.getPayload().containsKey(claimVariables.getExpiry())) {
                tokenExp = (Integer) token.getPayload().get(claimVariables.getExpiry());
            } else {
                tokenExp = (Integer) token.getPayload().get(claimVariables.getExpiration());
            }
            Long exp = Long.valueOf(tokenExp.longValue());
            exp = exp + expirationTolerance;
            Long now = Instant.now().getEpochSecond();
            if (now > exp) {
                throw new RuntimeException("JWT token is expired. exp: " + exp + " actual: " + now);
            }
        }
    }

    /**
     * Validate the nbf claim of the token
     *
     * @param token
     * @param checkNotBefore
     * @throws Runtime Exception
     */
    public void validateNotBefore(JWT token, Boolean checkNotBefore, ClaimsVariables claimVariables) {
        if (checkNotBefore != null && checkNotBefore) {
            Long nbf = ((Integer) token.getPayload().get(claimVariables.getNbf())).longValue();
            Long now = Instant.now().getEpochSecond();
            if (now < nbf) {
                throw new RuntimeException("JWT token is not yet valid. nbf: " + nbf + " actual: " + now);
            }
        }
    }

    /**
     * Validate the scopes of the token. This method is executed if the scopes are
     * provided by the user
     *
     * @param token
     * @param scopes
     * @throws Runtime Exception
     */
    @SuppressWarnings("unchecked")
    public void validateScope(JWT token, List<String> scopes, ClaimsVariables claimVariables) {
        boolean result = false;

        List<String> tokenScopes = new ArrayList<String>();
        if (token.getPayload().containsKey(claimVariables.getScp())) {
            tokenScopes = resolveAsList(token.getPayload().get(claimVariables.getScp()));

        } else if (token.getPayload().containsKey(claimVariables.getScope())) {
            tokenScopes = resolveAsList(token.getPayload().get(claimVariables.getScope()));
        } else {
            tokenScopes = resolveAsList(token.getPayload().get(claimVariables.getScopes()));
        }
        logger.debug("Token Scopes {} ", tokenScopes.toString());
        result = validateClaimsAsList(scopes, result, tokenScopes);

        if (!result) {
            throw new RuntimeException("JWT token does not have the valid scope: " + tokenScopes.toString()
                    + " required scope: " + scopes.toString());
        }
    }

    private boolean validateClaimsAsList(List<String> userClaims, boolean result, List<String> tokenClaims) {
        for (String userClaim : userClaims) {
            logger.debug("provided userClaim {} ", userClaim);
            for (String tokenClaim : tokenClaims) {
                logger.debug("Token Scope {} ", tokenClaim);
                if (tokenClaim.trim().equalsIgnoreCase(userClaim.trim())) {
                    result = true;
                }
            }
        }
        return result;
    }


    // unsecured tokens
    public void validateUnsecuredToken(JWT token, Boolean allowUnsecuredTokens) {
        if (token.isUnsecure() && !allowUnsecuredTokens) {
            throw new RuntimeException("Unsecured tokens are not valid by configuration.");
        }
    }

    private List<String> resolveAsList(Object claims) {
        List<String> claimsAsList = new ArrayList<>();
        if (claims instanceof List) {
            logger.debug("Claim is List");
            claimsAsList = (List<String>) claims;
        }
        if (claims instanceof String) {
            String scopeStr = claims.toString();
            logger.debug("Resolving claim {} ", scopeStr);
            if (scopeStr.contains(" ")) {
                logger.debug("claim contains Spaces");
                claimsAsList = new ArrayList<String>(Arrays.asList(scopeStr.split(" ")));
            } else if (scopeStr.contains(",")) {
                logger.debug("Claim contains comma");
                claimsAsList = new ArrayList<String>(Arrays.asList(scopeStr.split(",")));
            } else {
                claimsAsList.add(String.valueOf(claims));
            }
            logger.debug("Claim List {} ", claimsAsList.toString());
        }
        return claimsAsList;
    }

    /**
     * Validate custom claims provided by the user
     *
     * @param token
     * @param claims
     */
    public void validateCustomClaims(JWT token, Map<String, String> claims) {
        Iterator<String> iterator = claims.keySet().iterator();
        while (iterator.hasNext()) {
            String key = iterator.next();
            String claimsValue = claims.get(key);
            String tokenValue = (String) token.getPayload().get(key);
            if (!claimsValue.equalsIgnoreCase(tokenValue)) {
                throw new RuntimeException("Custom claims do not match");
            }
        }
    }
    
    /**
     * Retrieve issuer from the token
     * Enhancement as per 22 july 2023
     * @param token
     * @throws Runtime Exception
     */
    
    public String retrieveIssuer(JWT token, ClaimsVariables claimVariables) {
        
            String iss = "";
            if (token.getPayload().containsKey(claimVariables.getIss())) {
                iss = (String) token.getPayload().get(claimVariables.getIss());
            } else {
                iss = (String) token.getPayload().get(claimVariables.getIssuer());
            }
            return iss;
            //if (iss == null) {
                //throw new RuntimeException("JWT payload does not contain 'iss/issuer' claim");
            //}
           
        
    }

}
