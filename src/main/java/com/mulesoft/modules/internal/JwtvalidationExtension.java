package com.mulesoft.modules.internal;

import org.mule.runtime.extension.api.annotation.Extension;
import org.mule.runtime.extension.api.annotation.Configurations;
import org.mule.runtime.extension.api.annotation.dsl.xml.Xml;


/**
 * @since 01 August 2018
 * @version 1.0.0
 * This is the main class of an extension, is the entry point from which configurations, connection providers, operations
 * and sources are going to be declared.
 */
@Xml(prefix = "jwt-validation")
@Extension(name = "Jwt-validation")
@Configurations(JwtvalidationConfiguration.class)
public class JwtvalidationExtension {

}
