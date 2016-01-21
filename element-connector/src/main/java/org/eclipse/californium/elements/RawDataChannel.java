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
 *    Martin Lanter - architect and initial implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Documentation improvements
 ******************************************************************************/
package org.eclipse.californium.elements;

/**
 * A processor for messages received from the network layer.
 * 
 * Applications should register an implementation of this interface with
 * a <code>Connector</code> via its {@link Connector#setRawDataReceiver(RawDataChannel)}
 * method in order to get notified about incoming messages.
 * 
 * Applications should use the {@link Connector#send(RawData)} method to send
 * messages to receivers connected via the network.
 */
public interface RawDataChannel {

	/**
	 * Processes a raw message received from the network.
	 * 
	 * It is assumed that an implementation can either derive the message format
	 * by introspection or knows upfront about the message format to expect.
	 * 
	 * An implementation of this method should return quickly in order to improve
	 * message processing throughput. In cases where processing of a message is expected
	 * to take some time, implementations should consider off-loading the processing of the
	 * messages to a separate <code>Thread</code>, e.g. by employing a
	 * <code>java.util.concurrent.ExecutorService</code>.
	 * 
	 * @param raw
	 *            the raw message to process
	 */
	public void receiveData(RawData raw);

}
