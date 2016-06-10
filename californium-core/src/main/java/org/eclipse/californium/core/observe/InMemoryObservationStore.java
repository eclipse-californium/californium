/*******************************************************************************
 * Copyright (c) 2016 Sierra Wireless and others.
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
 ******************************************************************************/
package org.eclipse.californium.core.observe;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Exchange.KeyToken;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.core.network.serialization.Serializer;
import org.eclipse.californium.elements.CorrelationContext;
import org.eclipse.californium.elements.RawData;

public class InMemoryObservationStore implements ObservationStore {

	private Map<KeyToken, Observation> map = new ConcurrentHashMap<>();

	@Override
	public void add(Observation obs) {
		if (obs != null) {
			map.put(new KeyToken(obs.getRequest().getToken()), obs);
		}
	}

	@Override
	public Observation get(byte[] token) {
		Observation obs = map.get(new KeyToken(token));
		if (obs != null) {
			RawData serialize = Serializer.serialize(obs.getRequest(), null);
			DataParser parser = new DataParser(serialize.getBytes());
			Request newRequest = parser.parseRequest();
			return new Observation(newRequest, obs.getContext());
		}
		return null;
	}

	@Override
	public void remove(byte[] token) {
		map.remove(new KeyToken(token));
	}

	public boolean isEmpty(){
		return map.isEmpty();
	}

	public int getSize() {
		return map.size();
	}

	public void clear() {
		map.clear();
	}

	@Override
	public void setContext(byte[] token, CorrelationContext ctx) {
		Observation obs = map.get(new KeyToken(token));
		if (obs != null) {
			map.put(new KeyToken(token), new Observation(obs.getRequest(), ctx));
		}
	}
}
