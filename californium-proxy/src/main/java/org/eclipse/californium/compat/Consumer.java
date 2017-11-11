/*******************************************************************************
 * Copyright (c) 2017 NTNU Gjøvik and others.
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
 *    Martin Storø Nyfløtt (NTNU Gjøvik) - performance improvements to HTTP cross-proxy
 ******************************************************************************/

package org.eclipse.californium.compat;

/**
 * Backport of the class java.util.function.Consumer<T>
 * @param <T> Type that the consumer will receives.
 */
public interface Consumer<T> {
    /**
     * Executed when a said action is sent to the consumer.
     * @param result Result of some action.
     */
    public void accept(T result);
}
