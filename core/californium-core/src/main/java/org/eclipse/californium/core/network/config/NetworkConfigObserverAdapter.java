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
package org.eclipse.californium.core.network.config;


public class NetworkConfigObserverAdapter implements NetworkConfigObserver {

	@Override
	public void changed(String key, Object value) {
		// do nothing
	}

	@Override
	public void changed(String key, String value) {
		// do nothing
	}

	@Override
	public void changed(String key, int value) {
		// do nothing
	}

	@Override
	public void changed(String key, long value) {
		// do nothing
	}

	@Override
	public void changed(String key, float value) {
		// do nothing
	}

	@Override
	public void changed(String key, double value) {
		// do nothing
	}

	@Override
	public void changed(String key, boolean value) {
		// do nothing
	}
	
}
