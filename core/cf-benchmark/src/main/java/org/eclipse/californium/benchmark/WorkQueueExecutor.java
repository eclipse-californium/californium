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
package org.eclipse.californium.benchmark;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class WorkQueueExecutor implements ScheduledExecutorService {

	private ScheduledExecutorService timerService;
	private ThreadFactory threadFactory;
	
	private Worker[] workers;
	
	private int current = 0;
	
	public WorkQueueExecutor() {
		this(1);
	}
	
	public WorkQueueExecutor(int threads) {
		this(threads, Executors.newScheduledThreadPool(1));
	}
	
	public WorkQueueExecutor(int threads, ScheduledExecutorService timerService) {
		this(threads, timerService, Executors.defaultThreadFactory());
	}
	
	public WorkQueueExecutor(int threads, ScheduledExecutorService timerService, ThreadFactory threadFactory) {
		if (threads <= 0)
			throw new IllegalArgumentException("Executor must start at least 1 thread");
		if (timerService == null)
			throw new NullPointerException();
		if (threadFactory == null)
			throw new NullPointerException();
		
		this.timerService = timerService;
		this.threadFactory = threadFactory;

		workers = new Worker[threads];
		for (int i=0;i<threads;i++) {
			workers[i] = new Worker();
			this.threadFactory.newThread(workers[i]).start();
		}
	}
	
	@Override
	public void execute(Runnable command) {
		workers[current++ % workers.length].queue.offer(command);
	}

	@Override
	public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
		return timerService.schedule(command, delay, unit);
	}

	@Override
	public <V> ScheduledFuture<V> schedule(Callable<V> callable, long delay, TimeUnit unit) {
		return timerService.schedule(callable, delay, unit);
	}

	@Override
	public ScheduledFuture<?> scheduleAtFixedRate(Runnable command,
			long initialDelay, long period, TimeUnit unit) {
		return scheduleAtFixedRate(command, initialDelay, period, unit);
	}

	@Override
	public ScheduledFuture<?> scheduleWithFixedDelay(Runnable command,
			long initialDelay, long delay, TimeUnit unit) {
		return scheduleWithFixedDelay(command, initialDelay, delay, unit);
	}
	
	@Override
	public void shutdown() { 
		// timerService.shutdown();
		throw new UnsupportedOperationException();
	}

	@Override
	public List<Runnable> shutdownNow() {
		// timerService.shutdownNow();
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isShutdown() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isTerminated() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
		throw new UnsupportedOperationException();
	}

	@Override
	public <T> Future<T> submit(Callable<T> task) {
		throw new UnsupportedOperationException();
	}

	@Override
	public <T> Future<T> submit(Runnable task, T result) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Future<?> submit(Runnable task) {
		throw new UnsupportedOperationException();
	}

	@Override
	public <T> List<Future<T>> invokeAll(Collection<? extends Callable<T>> tasks)
			throws InterruptedException {
		throw new UnsupportedOperationException();
	}

	@Override
	public <T> List<Future<T>> invokeAll(
			Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit)
			throws InterruptedException {
		throw new UnsupportedOperationException();
	}

	@Override
	public <T> T invokeAny(Collection<? extends Callable<T>> tasks) throws InterruptedException, ExecutionException {
		throw new UnsupportedOperationException();
	}

	@Override
	public <T> T invokeAny(Collection<? extends Callable<T>> tasks,
			long timeout, TimeUnit unit) throws InterruptedException,
			ExecutionException, TimeoutException {
		throw new UnsupportedOperationException();
	}
	
	private static class Worker implements Runnable {
		
		private BlockingQueue<Runnable> queue = new LinkedBlockingQueue<Runnable>();
		
		public void run() {
			// TODO: try catch, stop
			while (true) {
				try {
					Runnable command = queue.take();
					command.run();
					
				} catch (InterruptedException e) {
					e.printStackTrace(); // TODO: stop
					
				} catch (Exception e) {
					e.printStackTrace(); // TODO: log
				}
			}
		}
	}

}
