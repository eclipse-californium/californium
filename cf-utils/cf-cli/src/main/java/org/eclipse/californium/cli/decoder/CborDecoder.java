/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 *    Achim Kraus (Bosch.IO GmbH)     - moved from cf-plugtest-client
 ******************************************************************************/
package org.eclipse.californium.cli.decoder;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;

public class CborDecoder implements Decoder {

	@Override
	public String decode(byte[] payload) {
		try {
			CBORObject cborResponse = CBORObject.DecodeFromBytes(payload);
			return cborResponse.toString();
		} catch (CBORException ex) {
			ex.printStackTrace();
			throw ex;
		} catch (NullPointerException ex) {
			ex.printStackTrace();
			throw ex;
		}
	}

}