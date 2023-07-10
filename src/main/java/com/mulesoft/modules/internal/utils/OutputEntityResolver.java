package com.mulesoft.modules.internal.utils;

import java.util.HashMap;
import org.mule.metadata.api.model.MetadataType;
import org.mule.runtime.api.connection.ConnectionException;
import org.mule.runtime.api.metadata.MetadataContext;
import org.mule.runtime.api.metadata.MetadataResolvingException;
import org.mule.runtime.api.metadata.resolving.OutputTypeResolver;
import org.mule.runtime.module.extension.internal.capability.xml.schema.model.Any;

public class OutputEntityResolver implements OutputTypeResolver<Any> {
	
	@Override
	public String getCategoryName() {
		return "JWT_Claims";
	}
	
	 @Override
	  public String getResolverName() {
	    return "OutputEntityResolver";
	  }

	@Override
	public MetadataType getOutputType(MetadataContext context, Any key)
			throws MetadataResolvingException, ConnectionException {
		return context.getTypeLoader().load(HashMap.class);
	}

}