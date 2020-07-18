/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Joakim Brorsson
 *    Ludwig Seitz (RISE SICS)
 *    Tobias Andersson (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.EndpointContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;

/**
 * 
 * Provides option handling methods necessary for OSCORE mechanics.
 *
 */
public class OptionJuggle {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(OptionJuggle.class);
	
	private static List<Integer> allEOptions = populateAllEOptions();

	private static List<Integer> populateAllEOptions() {
		List<Integer> allEOptions = new ArrayList<Integer>();
		allEOptions.add(OptionNumberRegistry.IF_MATCH);
		allEOptions.add(OptionNumberRegistry.ETAG);
		allEOptions.add(OptionNumberRegistry.IF_NONE_MATCH);
		allEOptions.add(OptionNumberRegistry.OBSERVE);
		allEOptions.add(OptionNumberRegistry.LOCATION_PATH);
		allEOptions.add(OptionNumberRegistry.URI_PATH);
		allEOptions.add(OptionNumberRegistry.CONTENT_FORMAT);
		allEOptions.add(OptionNumberRegistry.MAX_AGE);
		allEOptions.add(OptionNumberRegistry.URI_QUERY);
		allEOptions.add(OptionNumberRegistry.ACCEPT);
		allEOptions.add(OptionNumberRegistry.LOCATION_QUERY);
		allEOptions.add(OptionNumberRegistry.BLOCK2);
		allEOptions.add(OptionNumberRegistry.BLOCK1);
		allEOptions.add(OptionNumberRegistry.SIZE2);
		allEOptions.add(OptionNumberRegistry.SIZE1);
		return allEOptions;
	}

	/**
	 * Prepare a set or original CoAP options for unprotected use with OSCore.
	 * 
	 * @param options the original options
	 * 
	 * @return the OSCore-U option set
	 */
	public static OptionSet prepareUoptions(OptionSet options) {
		boolean hasProxyUri = options.hasProxyUri();
		boolean hasUriHost = options.hasUriHost();
		boolean hasUriPort = options.hasUriPort();
		boolean hasProxyScheme = options.hasProxyScheme();
		boolean hasMaxAge = options.hasMaxAge();
		boolean hasObserve = options.hasObserve();

		OptionSet ret = new OptionSet();

		if (hasUriHost) {
			ret.setUriHost(options.getUriHost());
		}

		if (hasUriPort) {
			ret.setUriPort(options.getUriPort());
		}

		if (hasMaxAge) {
			ret.setMaxAge(options.getMaxAge());
		}

		if (hasProxyScheme) {
			ret.setProxyScheme(options.getProxyScheme());
		}

		if (hasObserve) {
			ret.setObserve(options.getObserve());
		}

		if (hasProxyUri) {
			String proxyUri = options.getProxyUri();
			proxyUri = proxyUri.replace("coap://", "");
			proxyUri = proxyUri.replace("coaps://", "");
			int i = proxyUri.indexOf('/');
			if (i >= 0) {
				proxyUri = proxyUri.substring(0, i);
			}
			proxyUri = "coap://" + proxyUri;
			ret.setProxyUri(proxyUri);
		}

		byte[] oscore = options.getOscore();
		if (oscore != null) {
			ret.setOscore(oscore);
		}

		return ret;
	}

	/**
	 * Prepare a set or original CoAP options for encryption with OSCore.
	 * 
	 * @param options the original CoAP options
	 * 
	 * @return the option to be encrypted
	 */
	public static OptionSet prepareEoptions(OptionSet options) {
		OptionSet ret = new OptionSet();

		for (Option o : options.asSortedList()) {
			switch (o.getNumber()) {

			case OptionNumberRegistry.URI_HOST:
			case OptionNumberRegistry.URI_PORT:
			case OptionNumberRegistry.PROXY_SCHEME:
			case OptionNumberRegistry.OSCORE:
				// do not encrypt
				break;
			case OptionNumberRegistry.PROXY_URI:
				// create Uri-Path and Uri-Query
				String proxyUri = o.getStringValue();
				proxyUri = proxyUri.replace("coap://", "");
				proxyUri = proxyUri.replace("coaps://", "");
				int i = proxyUri.indexOf('/');
				if (i >= 0) {
					proxyUri = proxyUri.substring(i + 1, proxyUri.length());
				} else {// No Uri-Path and Uri-Query
					break;
				}
				i = proxyUri.indexOf("?");
				String uriPath = proxyUri;
				String uriQuery = null;
				if (i >= 0) {
					uriPath = proxyUri.substring(0, i);
					uriQuery = proxyUri.substring(i + 1, proxyUri.length());
				}

				if (uriPath != null) {
					ret.setUriPath(uriPath);
				}

				if (uriQuery != null) {
					String[] uriQueries = uriQuery.split("&");
					for (int idx = 0; idx < uriQueries.length; idx++) {
						ret.setUriQuery(uriQueries[idx]);
					}
				}
				break;
			default: // default is encrypt
				ret.addOption(o);
			}
		}
		return ret;
	}

	/**
	 * Returns a new OptionSet, result, which doesn't contain any e options
	 * 
	 * @param optionSet the options
	 * @return a new optionSet which have had the non-special e options removed
	 */
	public static OptionSet discardEOptions(OptionSet optionSet) {
		LOGGER.info("Removing inner only E options from the outer options");
		OptionSet result = new OptionSet();
		
		for (Option opt : optionSet.asSortedList()) {
			if (!allEOptions.contains(opt.getNumber())) {
				result.addOption(opt);
			}
		}
		return result;
	}

	/**
	 * Sets the fake code in the coap header and returns the real code.
	 * 
	 * @param request the request that receives its fake code.
	 * @return realCode the real code.
	 */
	public static Request setFakeCodeRequest(Request request) {
		Code fakeCode = request.getOptions().hasObserve() ? Code.FETCH : Code.POST;
		return requestWithNewCode(request, fakeCode);
	}

	/**
	 * Sets the Request's CoAP Code with realCode
	 * 
	 * @param request the request that receives its real code
	 * @param realCode the real code
	 * @return request with real code.
	 */
	public static Request setRealCodeRequest(Request request, Code realCode) {
		return requestWithNewCode(request, realCode);
	}

	/**
	 * Sets the fake code in the coap header and returns the real code.
	 * 
	 * @param response the response that receives its fake code.
	 * @return realCode the real code.
	 */
	public static Response setFakeCodeResponse(Response response) {
		return responseWithNewCode(response, ResponseCode.CHANGED);
	}

	/**
	 * Sets the realCode for a response
	 * 
	 * @param response response
	 * @param realCode real code
	 * @return response with real code
	 */
	public static Response setRealCodeResponse(Response response, ResponseCode realCode) {
		return responseWithNewCode(response, realCode);
	}

	/**
	 * Change the CoAP Code of the request to code
	 * 
	 * @param request the Request having its CoAP Code changed
	 * @param code the new CoAP Code
	 */
	private static Request requestWithNewCode(Request request, Code code) {
		OptionSet options = request.getOptions();
		byte[] payload = request.getPayload();
		Token token = request.getToken();
		EndpointContext destinationContext = request.getDestinationContext();
		EndpointContext sourceContext = request.getSourceContext();
		List<MessageObserver> messageObservers = request.getMessageObservers();
		int mid = request.getMID();
		Type type = request.getType();
		Map<String, String> userContext = request.getUserContext();

		Request newRequest = new Request(code);

		newRequest.setOptions(options);
		newRequest.setPayload(payload);
		newRequest.setToken(token);
		newRequest.setDestinationContext(destinationContext);
		newRequest.setSourceContext(sourceContext);
		newRequest.addMessageObservers(messageObservers);
		newRequest.setMID(mid);
		newRequest.setType(type);
		newRequest.setUserContext(userContext);

		return newRequest;
	}

	/**
	 * Change the ResponseCode of the response to code
	 * 
	 * @param response the Response having its ResponseCode changed
	 * @param code the new ResponseCode
	 */
	private static Response responseWithNewCode(Response response, ResponseCode code) {
		OptionSet options = response.getOptions();
		byte[] payload = response.getPayload();
		Token token = response.getToken();
		EndpointContext destinationContext = response.getDestinationContext();
		EndpointContext sourceContext = response.getSourceContext();
		List<MessageObserver> messageObservers = response.getMessageObservers();
		int mid = response.getMID();
		Type type = response.getType();
		Long rtt = response.getRTT();

		Response newResponse = new Response(code);

		newResponse.setOptions(options);
		newResponse.setPayload(payload);
		newResponse.setToken(token);
		newResponse.setDestinationContext(destinationContext);
		newResponse.setSourceContext(sourceContext);
		newResponse.addMessageObservers(messageObservers);
		newResponse.setMID(mid);
		newResponse.setType(type);
		if (rtt != null) {
			newResponse.setRTT(rtt);
		}

		return newResponse;
	}

	/**
	 * Merges two optionSets and returns the merge. Priority is eOptions
	 * 
	 * @param eOptions priority options
	 * @param uOptions options to be added
	 * @return merged OptionSet
	 */
	public static OptionSet merge(OptionSet eOptions, OptionSet uOptions) {

		List<Option> u = uOptions.asSortedList();

		for (Option tmp : u) {
			if (!eOptions.hasOption(tmp.getNumber())) {
				eOptions.addOption(tmp);
			}
		}
		return eOptions;
	}

	/**
	 * Retrieve RID value from an OSCORE option.
	 * 
	 * @param oscoreOption the OSCORE option
	 * @return the RID value
	 */
	static byte[] getRid(byte[] oscoreOption) {
		if (oscoreOption.length == 0) {
			return null;
		}
	
		// Parse the flag byte
		byte flagByte = oscoreOption[0];
		int n = flagByte & 0x07;
		int k = flagByte & 0x08;
		int h = flagByte & 0x10;
	
		byte[] kid = null;
		int index = 1;
	
		// Partial IV
		index += n;
	
		// KID Context
		if (h != 0) {
			int s = oscoreOption[index];
			index += s + 1;
		}
	
		// KID
		if (k != 0) {
			kid = Arrays.copyOfRange(oscoreOption, index, oscoreOption.length);
		}
	
		return kid;
	}

	/**
	 * Retrieve ID Context value from an OSCORE option.
	 * 
	 * @param oscoreOption the OSCORE option
	 * @return the ID Context value
	 */
	static byte[] getIDContext(byte[] oscoreOption) {
		if (oscoreOption.length == 0) {
			return null;
		}

		// Parse the flag byte
		byte flagByte = oscoreOption[0];
		int n = flagByte & 0x07;
		int h = flagByte & 0x10;

		byte[] kidContext = null;
		int index = 1;

		// Partial IV
		index += n;

		// KID Context
		if (h != 0) {
			int s = oscoreOption[index];
			kidContext = Arrays.copyOfRange(oscoreOption, index + 1, index + 1 + s);
			index += s + 1;
		}

		return kidContext;
	}

}
