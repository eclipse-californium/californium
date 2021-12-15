/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.elements.util.PublicAPIExtension;

/**
 * CoapStack is what CoapEndpoint uses to send messages through distinct layers.
 * 
 * @since 3.1
 */
@PublicAPIExtension(type = CoapStack.class)
public interface ExtendedCoapStack extends CoapStack {

	<T extends Layer> T getLayer(Class<T> type);
}
