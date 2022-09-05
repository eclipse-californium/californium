/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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

package org.eclipse.californium.proxy2.resources;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.DelivererException;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.proxy2.CoapUriTranslator;
import org.eclipse.californium.proxy2.TranslationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Forward proxy message deliverer
 * 
 * Delivers message either to proxy resources registered for the destination
 * scheme, or, to local resources using the request's path.
 * 
 * A request is considered for the forward-proxy, if either
 * <ul>
 * <li>a proxy-uri or a proxy-scheme option is contained, or,</li>
 * <li>a uri-host and/or uri-port option is contained in the request, and the
 * destination defined by this options is not contained in the exposed service
 * addresses</li>
 * </ul>
 * For request considered for the forward-proxy, the destination scheme is
 * determined by calling {@link CoapUriTranslator#getDestinationScheme(Request)}
 * of the provided translator. If a {@link ProxyCoapResource} was added, which
 * handles this destination scheme, the request delivered to that resource. For
 * none-compliant proxies, the translator implementation may return {@code null}
 * from {@link CoapUriTranslator#getDestinationScheme(Request)} for specific
 * request to bypass the forward-proxy processing.
 * 
 * Requests not processed by the forward-proxy are processed as standard request
 * by the coap-server.
 */
public class ForwardProxyMessageDeliverer extends ServerMessageDeliverer {

	private static final Logger LOGGER = LoggerFactory.getLogger(ForwardProxyMessageDeliverer.class);

	/**
	 * Translator to determine destination scheme.
	 * 
	 * @see CoapUriTranslator#getDestinationScheme(Request)
	 */
	private final CoapUriTranslator translator;
	/**
	 * Map schemes to proxy resources.
	 */
	private final Map<String, Resource> scheme2resource;
	/**
	 * Set of exposed services. Using containers, this may be different from the
	 * local interfaces.
	 */
	private final Set<InetSocketAddress> exposedServices;
	/**
	 * Set of exposed addresses. Using containers, this may be different from
	 * the local interfaces.
	 */
	private final Set<InetAddress> exposedHosts;
	/**
	 * Set of exposed ports. Using containers, this may be different from the
	 * local ports.
	 */
	private final Set<Integer> exposedPorts;

	/**
	 * Indicates, that {@link #addExposedServiceAddresses(InetSocketAddress...)}
	 * was called with a any address.
	 * 
	 * @since 3.0
	 */
	private boolean exposedAnyAddress;

	/**
	 * Datagram socket to resolve the local address.
	 * 
	 * @since 3.0
	 */
	private DatagramSocket localAddressResolverSocket;

	/**
	 * Create message deliverer with forward-proxy support.
	 * 
	 * @param root root resource of coap-proxy-server. Used for mixed proxies or
	 *            coap servers, if requests are intended to be also delivered
	 *            according their uri-path. May be {@code null}, if only used
	 *            for a forward proxy and requests are no intended to be
	 *            delivered using their uri path.
	 * @param translator translator for destination-scheme.
	 *            {@link CoapUriTranslator#getDestinationScheme(Request)} is
	 *            used to determine this destination scheme for forward-proxy
	 *            implementations. The translator may return {@code null} to
	 *            bypass the forward-proxy processing for a request.
	 * @deprecated use
	 *             {@link #ForwardProxyMessageDeliverer(Resource, CoapUriTranslator, Configuration)}
	 *             instead
	 */
	@Deprecated
	public ForwardProxyMessageDeliverer(Resource root, CoapUriTranslator translator) {
		this(root, translator, null);
	}

	/**
	 * Create message deliverer with forward-proxy support.
	 * 
	 * @param root root resource of coap-proxy-server. Used for mixed proxies or
	 *            coap servers, if requests are intended to be also delivered
	 *            according their uri-path. May be {@code null}, if only used
	 *            for a forward proxy and requests are no intended to be
	 *            delivered using their uri path.
	 * @param translator translator for destination-scheme.
	 *            {@link CoapUriTranslator#getDestinationScheme(Request)} is
	 *            used to determine this destination scheme for forward-proxy
	 *            implementations. The translator may return {@code null} to
	 *            bypass the forward-proxy processing for a request.
	 * @param config configuration.
	 * @since 3.6
	 */
	public ForwardProxyMessageDeliverer(Resource root, CoapUriTranslator translator, Configuration config) {
		super(root, config);
		this.translator = translator;
		this.scheme2resource = new HashMap<String, Resource>();
		this.exposedServices = new HashSet<>();
		this.exposedPorts = new HashSet<>();
		this.exposedHosts = new HashSet<>();
	}

	/**
	 * Create message deliverer with forward-proxy support.
	 * 
	 * @param proxyCoapResource proxy-coap-resource. Use the resources
	 *            {@link ProxyCoapResource#getUriTranslater()} to determine the
	 *            destination scheme.
	 * @since 2.4
	 */
	public ForwardProxyMessageDeliverer(ProxyCoapResource proxyCoapResource) {
		this(null, proxyCoapResource.getUriTranslater(), null);
		addProxyCoapResources(proxyCoapResource);
	}

	/**
	 * Add exposed service address to suppress recursive requests.
	 * 
	 * If a {@link InetAddress#isAnyLocalAddress()} is provided, sets
	 * {@link #exposedAnyAddress}.
	 * 
	 * @param exposed list of exposed interface addresses to suppress recursive
	 *            proxy request. The exposed interfaces may differ from the
	 *            local one, if containers are used.
	 * @return this forward proxy message deliverer
	 * @throws NullPointerException if {@code null} is provided
	 * @throws IllegalArgumentException if list is empty
	 */
	public ForwardProxyMessageDeliverer addExposedServiceAddresses(InetSocketAddress... exposed) {
		if (exposed == null) {
			throw new NullPointerException("exposed interfaces must not be null!");
		}
		if (exposed.length == 0) {
			throw new IllegalArgumentException("exposed interfaces must not be empty!");
		}
		boolean exposedAnyAddress = false;
		Collection<InetAddress> all = NetworkInterfacesUtil.getNetworkInterfaces();
		for (InetSocketAddress inetAddress : exposed) {
			LOGGER.info("address {}", inetAddress);
			this.exposedPorts.add(inetAddress.getPort());
			InetAddress address = inetAddress.getAddress();
			if (address.isAnyLocalAddress()) {
				exposedAnyAddress = true;
				for (InetAddress eAddress : all) {
					this.exposedServices.add(new InetSocketAddress(eAddress, inetAddress.getPort()));
					this.exposedHosts.add(eAddress);
				}
			} else {
				this.exposedServices.add(inetAddress);
				this.exposedHosts.add(address);
			}
		}
		for (Integer port : exposedPorts) {
			LOGGER.info("Exposed port {}", port);
		}
		for (InetAddress address : exposedHosts) {
			LOGGER.info("Exposed host {}", address);
		}
		for (InetSocketAddress inetAddress : exposedServices) {
			LOGGER.info("Exposed service {}", inetAddress);
		}
		if (exposedAnyAddress) {
			synchronized (this) {
				this.exposedAnyAddress = true;
			}
		}
		return this;
	}

	/**
	 * Add proxy coap resources as standard forward-proxies.
	 * 
	 * @param proxies list of proxy resources.
	 * @return this forward proxy message deliverer
	 * @throws NullPointerException if {@code null} is provided
	 * @throws IllegalArgumentException if list is empty
	 */
	public ForwardProxyMessageDeliverer addProxyCoapResources(ProxyCoapResource... proxies) {
		if (proxies == null) {
			throw new NullPointerException("proxies must not be null!");
		}
		if (proxies.length == 0) {
			throw new IllegalArgumentException("proxies must not be empty!");
		}
		for (ProxyCoapResource proxy : proxies) {
			Set<String> schemes = proxy.getDestinationSchemes();
			for (String scheme : schemes) {
				if (scheme2resource.put(scheme, proxy) != null) {
					LOGGER.warn("ambig proxy resource for scheme {}!", scheme);
				}
			}
		}
		return this;
	}

	/**
	 * Start local address resolver.
	 * 
	 * If data is received through an any-address, the address resolver tries to
	 * determine the local address used to send data back. Must be called after
	 * {@link #addExposedServiceAddresses(InetSocketAddress...)} with a
	 * {@link InetAddress#isAnyLocalAddress()}, otherwise the resolver is not
	 * required and not started.
	 * 
	 * @return {@code true}, if address resolver is running, {@code false}, if
	 *         not (caused by errors).
	 * @see #stopLocalAddressResolver()
	 * @since 3.0
	 */
	public synchronized boolean startLocalAddressResolver() {
		try {
			if (exposedAnyAddress && localAddressResolverSocket == null) {
				localAddressResolverSocket = new DatagramSocket();
			}
		} catch (SocketException e) {
			LOGGER.warn("");
		}
		return localAddressResolverSocket != null;
	}

	/**
	 * Stop local address resolver.
	 * 
	 * @see #startLocalAddressResolver()
	 * @since 3.0
	 */
	public synchronized void stopLocalAddressResolver() {
		if (localAddressResolverSocket != null) {
			localAddressResolverSocket.close();
			localAddressResolverSocket = null;
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Route proxy requests to registered proxy resources. Suppress forwarding
	 * of proxy request to own exposed interfaces reducing recursion.
	 * 
	 * @throws DelivererException if proxy scheme is not supported
	 * @since 3.0 (throws DelivererException)
	 */
	@Override
	protected Resource findResource(Exchange exchange) throws DelivererException {
		Resource resource = null;
		Request request = exchange.getRequest();
		OptionSet options = request.getOptions();
		boolean proxyOption = options.hasProxyUri() || options.hasProxyScheme();
		boolean hostOption = options.hasUriHost() || options.hasUriPort();
		boolean local = true;

		if (hostOption && !exposedServices.isEmpty()) {
			// check, if proxy is final destination.
			Integer port = options.getUriPort();
			String host = options.getUriHost();
			if (host == null) {
				if (exposedPorts.contains(port)) {
					// proxy is destination
					hostOption = false;
				} else {
					local = false;
				}
			} else {
				if (port == null) {
					try {
						InetAddress address = InetAddress.getByName(host);
						if (exposedHosts.contains(address)) {
							// proxy is destination
							hostOption = false;
						} else {
							local = false;
						}
					} catch (UnknownHostException e) {
						// destination not reachable
						hostOption = false;
					}
				} else {
					InetSocketAddress destination = new InetSocketAddress(host, port);
					if (destination.isUnresolved() || exposedServices.contains(destination)) {
						// destination not reachable or proxy is destination
						hostOption = false;
					} else {
						local = false;
					}
				}
			}
		}

		if (proxyOption || hostOption) {
			try {
				String scheme = translator.getDestinationScheme(request);
				if (scheme != null) {
					scheme = scheme.toLowerCase();
					resource = scheme2resource.get(scheme);
					if (resource == null) {
						throw new DelivererException(ResponseCode.PROXY_NOT_SUPPORTED, scheme + " not supported!", true);
					}
					if (options.getUriHost() == null) {
						// no URI-host
						InetSocketAddress localSocketAddress = request.getLocalAddress();
						if (localSocketAddress != null && localSocketAddress.getAddress().isAnyLocalAddress()) {
							// any local address
							InetAddress localAddress = resolveLocalAddress(request.getSourceContext().getPeerAddress());
							if (localAddress != null) {
								request.setLocalAddress(
										new InetSocketAddress(localAddress, localSocketAddress.getPort()));
							}
						}
					}
				} else {
					local = true;
				}
			} catch (TranslationException e) {
				LOGGER.debug("Bad proxy request", e);
			}
		}
		if (resource == null && local && getRootResource() != null) {
			// try to find local resource
			resource = super.findResource(exchange);
		}
		return resource;
	}

	/**
	 * Resolve local address.
	 * 
	 * If data is received through an any-address, the address resolver tries to
	 * determine the local address used to send data back.
	 * 
	 * @param destination the source address of the received message is used as
	 *            destination address to resolve the local address.
	 * @return resolved local address, or {@code null}, if not available.
	 */
	private synchronized InetAddress resolveLocalAddress(InetSocketAddress destination) {
		try {
			if (localAddressResolverSocket != null) {
				localAddressResolverSocket.connect(destination);
				InetAddress localAddress = localAddressResolverSocket.getLocalAddress();
				localAddressResolverSocket.disconnect();
				if (!localAddress.isAnyLocalAddress()) {
					return localAddress;
				}
			}
		} catch (SocketException e) {
		}
		return null;
	}
}
