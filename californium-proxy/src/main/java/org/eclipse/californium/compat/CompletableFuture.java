/*******************************************************************************
 * Copyright (c) 2017 NTNU Gjøvik and others.
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
 *    Martin Storø Nyfløtt (NTNU Gjøvik) - performance improvements to HTTP cross-proxy
 ******************************************************************************/

package org.eclipse.californium.compat;

/**
 * Backport of the class introduced in Java java.util.concurrent.CompletableFuture<T>.
 * @param <T> Type of the result the future shall complete with.
 */
public class CompletableFuture<T> {
    private T result;
    private Consumer<T> consumer;

    /**
     * Sets the result of the action completed with the future.
     * The result will be executed on the consumer registered on this future.
     * @param result Result of the future.
     */
    public void complete(T result) {
        synchronized (this) {
            this.result = result;

            if (consumer != null) {
                consumer.accept(result);
            }
        }
    }

    /**
     * Sets the consumer of the future.
     * @param consumer Will receive a notification one the result of the
     *                 future has been set.
     */
    public void thenAccept(Consumer<T> consumer) {
        synchronized (this) {
            this.consumer = consumer;

            if (result != null) {
                consumer.accept(result);
            }
        }
    }
}
