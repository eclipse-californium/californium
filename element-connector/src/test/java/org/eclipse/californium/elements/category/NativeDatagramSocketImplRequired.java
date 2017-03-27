/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - Initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.category;

/**
 * A marker interface for test cases that requires the native DatagamSocketImpl for
 * real network operations.
 * 
 * Be careful when design such test, so that dropping and reordering of messages
 * doesn't break your test!
 */
public interface NativeDatagramSocketImplRequired {
}
