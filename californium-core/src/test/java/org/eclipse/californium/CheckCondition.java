/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial implementation
 ******************************************************************************/
package org.eclipse.californium;

import org.eclipse.californium.elements.util.TestCondition;

/**
 * Interface to "poll" on conditions, where the API doesn't support a
 * notification.
 * @deprecated use {@link TestCondition} instead
 */
@Deprecated
public interface CheckCondition extends TestCondition {

}
