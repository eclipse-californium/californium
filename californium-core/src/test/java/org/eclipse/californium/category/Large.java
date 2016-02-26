/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - Initial creation
 ******************************************************************************/
package org.eclipse.californium.category;

/**
 * A marker interface for test cases that need a large amount of time to execute.
 * 
 * Typical tests falling in this category include end-to-end functional tests and
 * tests involving conversational state. 
 */
public interface Large {
}
