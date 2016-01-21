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
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;


/**
 * A factory for {@link Connector} objects.
 * 
 * An implementation will usually create one type of Connectors only, e.g.
 * standard unencrypted UDP connectors vs. encrypted DTLS based connectors.
 */
public interface ConnectorFactory {

	/**
	 * Creates a new network connector.
	 * 
	 * The connectors created by this method are <em>not</em> started yet.
	 * 
	 * @param socketAddress the IP address and port to connect to
	 * @return the connector
	 */
	Connector newConnector(InetSocketAddress socketAddress);
}
