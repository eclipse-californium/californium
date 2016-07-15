/*******************************************************************************
 * Copyright (c) 2016 Amazon Web Services.
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
 *    Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import org.eclipse.californium.elements.Connector;

/**
 * Marker interface to allow backwards compatible identification of TCP connector for Californium 1.1 release. The
 * proper implementation (within 2.0 release) will extend {@link Connector} interface by adding {#code isSchemeSupport}
 * method to the interface.
 */
public interface TcpConnector {
}
