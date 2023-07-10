package com.mulesoft.modules.internal;

import org.mule.runtime.extension.api.annotation.Operations;
import org.mule.runtime.extension.api.annotation.param.Parameter;

import com.mulesoft.modules.internal.operations.AuthenticationHeaders;
import com.mulesoft.modules.internal.operations.GeneratePublicCertificates;
import com.mulesoft.modules.internal.operations.GetKeysFromJWKS;
import com.mulesoft.modules.internal.operations.ValidateToken;

/**
 * @since 01 August 2018
 * @version 1.0.0
 * This class represents an extension configuration, values set in this class are commonly used across multiple operations since
 * they represent something core from the extension.
 */
@Operations({ValidateToken.class, GetKeysFromJWKS.class, GeneratePublicCertificates.class, AuthenticationHeaders.class})
public class JwtvalidationConfiguration {

  @Parameter
  private String httpAuthorization;
  private String certificate;
  private String issuer;
  private String audience;
  private Integer expirationTolerance;
  private boolean checkExpiration;
  private boolean checkNotBefore;
  private boolean allowUnsecuredTokens;
  private String scopes;
  private String keys;

  public String getHttpAuthorization() {
    return httpAuthorization;
  }

  public String getCertificate() {
    return certificate;
  }

  public String getIssuer() {
    return issuer;
  }

  public String getAudience() {
    return audience;
  }

  public Integer getExpirationTolerance() {
    return expirationTolerance;
  }

  public boolean isCheckExpiration() {
    return checkExpiration;
  }

  public boolean isCheckNotBefore() {
    return checkNotBefore;
  }

  public boolean isAllowUnsecuredTokens() {
    return allowUnsecuredTokens;
  }

  public String getScopes() {
    return scopes;
  }

  public String getKeys() {
    return keys;
  }


}
