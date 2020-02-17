/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.server.resources;

import org.eclipse.californium.core.observe.ObserveRelation;

/**
 * An abstract adapter class for reacting to a resources's lifecylce events.
 * <p>
 * The methods in this class are empty.
 * <p>
 * Subclasses should override the methods for the events of interest.
 * <p>
 * An instance of the concrete resource observer can then be registered with a
 * resource using the resource's {@link Resource#addObserver(ResourceObserver)}.
 * @since 2.1
 */
public abstract class ResourceObserverAdapter implements ResourceObserver {

	@Override
	public void changedName(String old) {
	}

	@Override
	public void changedPath(String old) {
	}

	@Override
	public void addedChild(Resource child) {
	}

	@Override
	public void removedChild(Resource child) {
	}

	@Override
	public void addedObserveRelation(ObserveRelation relation) {
	}

	@Override
	public void removedObserveRelation(ObserveRelation relation) {
	}

}
