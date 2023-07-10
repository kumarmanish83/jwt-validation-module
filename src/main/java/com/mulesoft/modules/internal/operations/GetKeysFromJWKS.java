package com.mulesoft.modules.internal.operations;

import static org.mule.runtime.http.api.HttpConstants.Method.GET;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.TimeoutException;

import javax.inject.Inject;

import org.apache.commons.io.IOUtils;
import org.mule.runtime.api.lifecycle.CreateException;
import org.mule.runtime.api.tls.TlsContextFactory;
import org.mule.runtime.extension.api.annotation.param.MediaType;
import org.mule.runtime.http.api.HttpService;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.client.HttpClientConfiguration;
import org.mule.runtime.http.api.domain.message.request.HttpRequest;
import org.mule.runtime.http.api.domain.message.response.HttpResponse;

/**
 * @since 01 August 2018
 * @version 1.0.0
 * This class is a container for operations, every public method in this class
 * will be taken as an extension operation.
 * This class is used to get signing keys from JWKS service.
 */

public class GetKeysFromJWKS {
	
	@Inject
	private HttpService service;

	private HttpClient client;
	
	/**
	 * Go to jwks url and retrieve the keys required to create the certs
	 * @param host
	 * @param basePath
	 * @return
	 */
	@MediaType(value = "application/json")
	public String retrieveJwksKeys(String host, String basePath) {
		TlsContextFactory tlsContext;
		try {
			tlsContext = TlsContextFactory.builder().insecureTrustStore(true).build();
		} catch (CreateException e) {
			throw new RuntimeException("Can not retrieve JWKS", e);
		}
		HttpClientConfiguration httpClientConfig = new HttpClientConfiguration.Builder().setName(getClass().getName())
				.setTlsContextFactory(tlsContext).build();

		try {
			client = service.getClientFactory().create(httpClientConfig);
			client.start();
			HttpResponse response = client.send(
					HttpRequest.builder().uri("https://" + host + basePath).method(GET).build(), 10000, true, null);
			return getBodyFromResponse(response);
		} catch (IOException e) {
			throw new RuntimeException("Can not retrieve JWKS", e);

		} catch (TimeoutException e) {
			throw new RuntimeException("Can not retrieve JWKS", e);

		}
	}

	/**
	 * Capture the Http resposne
	 * @param response
	 * @return
	 * @throws IOException
	 */
	private String getBodyFromResponse(HttpResponse response) throws IOException {
		try (InputStream responseInputStream = response.getEntity().getContent()) {
			return IOUtils.toString(responseInputStream);
		}
	}

	/**
	 * Dispose the HTTP connection
	 */
	public void dispose() {
		if (client != null) {
			client.stop();
		}
	}

}
