package com.mulesoft.modules.internal.operations;

/**
 * @since 01 August 2018
 * @version 1.0.0
 * This operation class is to create/retrieve certificates from the response received from the JWKS service.
 * If x5c is present in the response from JWKS, store x5c value.
 * If x5c is absent in the response from JWLS, calculate the certificate using the modulus and exponent received from JWLKS.
 */

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.mulesoft.modules.internal.utils.CertificateUtils;

public class GeneratePublicCertificates {
	
	/**
	 * Module Operation to create certificates from Keys
	 * If x5c is present, take the certificate as-is, else create certificate from modulus and exponent
	 * @param keys
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public List<String> createCertificates(String keys) {
		CertificateUtils util = new CertificateUtils();
		List<String> certificates = new ArrayList<String>();
		JSONParser parser = new JSONParser();
		JSONObject keysJSON = null;
		try {
			keysJSON = (JSONObject) parser.parse(keys);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		JSONArray keysArray = (JSONArray) keysJSON.get("keys");
		Iterator<JSONObject> iterator = keysArray.iterator();
		while (iterator.hasNext()) {
			JSONObject key = iterator.next();
			if (key.containsKey("x5c")) {
				JSONArray x5cArrays = (JSONArray) key.get("x5c");
				String tempCert = "-----BEGIN CERTIFICATE-----\n" + x5cArrays.get(0).toString() + "\n-----END CERTIFICATE-----";
 				//certificates.add(x5cArrays.get(0).toString());
				certificates.add(tempCert);
			} else {
				certificates.add(util.isVerified(key));
			}
		}
		return certificates;
	}

}
