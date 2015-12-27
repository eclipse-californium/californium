/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;

public class ClientBlockwiseInterceptor implements MessageInterceptor {

	private StringBuilder buffer = new StringBuilder();
		
	@Override
	public void sendRequest(Request request) {
		buffer.append(
				String.format("\n%s [MID=%d, T=%s], %s, /%s%s%s%s    ----->",
				request.getType(), request.getMID(), request.getTokenString(), request.getCode(),
				request.getOptions().getUriPathString(),
				blockOptionString(1, request.getOptions().getBlock1()),
				blockOptionString(2, request.getOptions().getBlock2()),
				observeString(request.getOptions())));
	}

	@Override
	public void sendResponse(Response response) {
		buffer.append("ERROR: Server received "+response+"\n");
	}

	@Override
	public void sendEmptyMessage(EmptyMessage message) {
		buffer.append(
				String.format("\n%-19s                       ----->",
				String.format("%s [MID=%d], 0",message.getType(), message.getMID())
				));
	}

	@Override
	public void receiveRequest(Request request) {
		buffer.append("\nERROR: Server sent "+request+"\n");
	}

	@Override
	public void receiveResponse(Response response) {
		buffer.append(
				String.format("\n<-----   %s [MID=%d, T=%s], %s%s%s%s    ",
				response.getType(), response.getMID(), response.getTokenString(), response.getCode(),
				blockOptionString(1, response.getOptions().getBlock1()),
				blockOptionString(2, response.getOptions().getBlock2()),
				observeString(response.getOptions())));
	}

	@Override
	public void receiveEmptyMessage(EmptyMessage message) {
		buffer.append(
				String.format("\n<-----   %s [MID=%d], 0",
				message.getType(), message.getMID()));
	}
	
	public void log(String str) {
		buffer.append(str);
	}
	
	private String blockOptionString(int nbr, BlockOption option) {
		if (option == null) return "";
		return String.format(", %d:%d/%d/%d", nbr, option.getNum(),
				option.isM()?1:0, option.getSize());
	}
	
	private String observeString(OptionSet options) {
		if (options == null) return "";
		else if (!options.hasObserve()) return "";
		else return ", (observe="+options.getObserve()+")";
	}
	
	public String toString() {
		return buffer.append("\n").substring(1);
	}
	
	public void clear() {
		buffer = new StringBuilder();
	}

}
