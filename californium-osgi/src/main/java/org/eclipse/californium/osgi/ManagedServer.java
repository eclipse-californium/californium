/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla - OSGi support
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.osgi;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.Dictionary;
import java.util.HashSet;
import java.util.Set;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.server.ServerInterface;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.config.Configuration;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedService;
import org.osgi.util.tracker.ServiceTracker;
import org.osgi.util.tracker.ServiceTrackerCustomizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A managed Californium {@code ServerInterface} instance that can be configured using the OSGi
 * <i>Configuration Admin</i> service.
 * 
 * The service understands all configuration properties defined
 * by {@link CoapConfig}.
 * In particular, it uses the following properties to determine which endpoints the managed server
 * should listen on:
 * <ul>
 * <li>DEFAULT_COAP_PORT - The port to bind the default CoAP endpoint (non-secure) to.</li>
 * <li>DEFAULT_COAPS_PORT - The port to bind an (optional) secure (DTLS) endpoint to. In order for this to work,
 * the {@link EndpointFactory} provided via the constructor must support the creation of secure endpoints.
 * </li>
 * </ul>
 * 
 * This managed service uses the <i>white board</i> pattern for registering resources,
 * i.e. the service tracks Californium {@code Resource} instances being added to the OSGi service registry
 * and automatically adds them to the managed Californium {@code ServerInterface} instance.
 */
public class ManagedServer implements ManagedService, ServiceTrackerCustomizer<Resource, Resource>, ServerEndpointRegistry {

	private final static Logger LOGGER = LoggerFactory.getLogger(ManagedServer.class);

	private ServerInterface managedServer;
	private boolean running = false;
	private BundleContext context;
	private ServiceTracker<Resource, Resource> resourceTracker;
	private ServerInterfaceFactory serverFactory;
	private EndpointFactory endpointFactory;

	/**
	 * Sets all required collaborators.
	 * 
	 * Invoking this constructor is equivalent to invoking {@link #ManagedServer(BundleContext, EndpointFactory)}
	 * with {@code null} as the server factory.
	 * 
	 * @param bundleContext the bundle context to be used for tracking {@code Resource}s
	 * @param endpointFactory the factory to use for creating endpoints for the managed
	 * server
	 * @throws NullPointerException if any of the parameters is {@code null}
	 */
	public ManagedServer(BundleContext bundleContext, EndpointFactory endpointFactory) {
		this(bundleContext, null, endpointFactory);
	}

	/**
	 * Sets all required collaborators.
	 * 
	 * @param bundleContext the bundle context to be used for tracking {@code Resource}s
	 * @param serverFactory the factory to use for creating new server instances
	 * @param endpointFactory the factory to use for creating endpoints for the managed
	 * server
	 * @throws NullPointerException if the bundle context or endpoint factory is {@code null}
	 */
	public ManagedServer(BundleContext bundleContext, ServerInterfaceFactory serverFactory,
			EndpointFactory endpointFactory) {
		CoapConfig.register();
		if (bundleContext == null) {
			throw new NullPointerException("BundleContext must not be null");
		}
		if (endpointFactory == null) {
			throw new NullPointerException("EndpointFactory must not be null");
		}
		this.context = bundleContext;
		this.endpointFactory = endpointFactory;
		if (serverFactory != null) {
			this.serverFactory = serverFactory;
		} else {
			this.serverFactory= new ServerInterfaceFactory() {
				
				@Override
				public ServerInterface newServer(Configuration config) {
					int port = config.get(CoapConfig.COAP_PORT);
					if ( port == 0 )
					{
						port = CoAP.DEFAULT_COAP_PORT;
					}
					return newServer(config, port);
				}

				@Override
				public ServerInterface newServer(Configuration config, int... ports) {
					CoapServer server = new CoapServer(config, ports);
					return server;
				}
			};
		}
	}

	/**
	 * Updates the configuration properties of the wrapped Californium server.
	 * 
	 * If the server is running when this method is called by ConfigAdmin, the server
	 * is destroyed, a new instance is created using the given properties and finally
	 * started.
	 *  
	 * @param properties the properties to set on the server
	 */
	@Override
	public void updated(Dictionary<String, ?> properties)
			throws ConfigurationException {

		LOGGER.debug("Updating configuration of managed server instance");

		if (isRunning()) {
			stop();
		}

		Configuration networkConfig = Configuration.createStandardWithoutFile();
		if (properties != null) {
			networkConfig.add(properties);
		}

		// create server instance with CoAP endpoint on configured port
		managedServer = serverFactory.newServer(networkConfig);

		// add secure endpoint if configured
		int securePort = networkConfig.get(CoapConfig.COAP_SECURE_PORT);
		if ( securePort > 0 ) {
			Endpoint secureEndpoint = endpointFactory.getSecureEndpoint(
					networkConfig, new InetSocketAddress((InetAddress) null, securePort));
			if (secureEndpoint != null) {
				LOGGER.debug("Adding secure endpoint on address {}", secureEndpoint.getAddress());
				managedServer.addEndpoint(secureEndpoint);
			} else {
				LOGGER.warn("Secure endpoint has been configured in server properties but EndpointFactory does not support creation of secure Endpoints");
			}
		}

		managedServer.start();
		running = true;

		// start tracking resources registered by arbitrary bundles
		resourceTracker = new ServiceTracker<Resource, Resource>(context, Resource.class.getName(), this);
		resourceTracker.open();
	}

	private boolean isRunning() {
		return running;
	}

	/**
	 * Stops and destroys the managed server instance.
	 * 
	 * This method should be called by the {@code BundleActivator} that registered
	 * this managed service when the bundle is stopped.
	 */
	public void stop() {
		if (managedServer != null) {
			LOGGER.debug("Destroying managed server instance");
			if (resourceTracker != null) {
				// stop tracking Resources
				resourceTracker.close();
			}
			managedServer.destroy();
			running = false;
		}
	}

	
	/**
	 * Adds a Californium {@code Resource} to the managed Californium {@code Server}.
	 * 
	 * This method is invoked automatically by the {@code ServiceTracker} whenever
	 * a {@code Resource} is added to the OSGi service registry.
	 * 
	 * @param reference the {@code Resource} service that has been added
	 * @return the unmodified {@code Resource}
	 */
	@Override
	public Resource addingService(ServiceReference<Resource> reference) {
		Resource resource = context.getService(reference);
		if (resource != null) {
			LOGGER.debug("Adding resource [{}]", resource.getName());
			managedServer.add(resource);
		} else {
			LOGGER.debug("Failed adding resource for [{}], not available!", reference);
		}
		return resource;
	}

	/**
	 * Removes a Californium {@code Resource} from the managed Californium {@code Server}.
	 * 
	 * This method is invoked automatically by the {@code ServiceTracker} whenever
	 * a {@code Resource} is removed from the OSGi service registry.
	 * 
	 * @param reference the reference to the {@code Resource} service that has been removed
	 * @param service the service object
	 */
	@Override
	public void removedService(ServiceReference<Resource> reference,
			Resource service) {
		LOGGER.debug("Removing resource [{}]", service.getName());
		managedServer.remove(service);
		context.ungetService(reference);
	}

	/**
	 * Does nothing as the Californium server does not need to be informed about
	 * updated service registration properties of a {@code Resource}.
	 * 
	 * @param reference the updated {@code Resource} service reference
	 * @param service the corresponding {@code Resource} instance
	 */
	@Override
	public void modifiedService(ServiceReference<Resource> reference,
			Resource service) {
		// nothing to do
	}

	@Override
	public Endpoint getEndpoint(InetSocketAddress address) {
		return managedServer.getEndpoint(address);
	}

	@Override
	public Endpoint getEndpoint(int port) {
		return managedServer.getEndpoint(port);
	}

	@Override
	public Set<Endpoint> getAllEndpoints() {

		return Collections.unmodifiableSet(new HashSet<Endpoint>(managedServer.getEndpoints()));
	}
}
