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
 *    Bosch Software Innovations GmbH - initial creation
 *                                      derived from HelloWorldServer example
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;

public class SimpleFileServer extends CoapServer {
	private static final Logger LOG = LoggerFactory.getLogger(SimpleFileServer.class.getName());

	private static final int COAP_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_PORT);
	private static final String DEFAULT_PATH = "data";

	/*
	 * Application entry point.
	 */
	public static void main(String[] args) {

		try {
			String filesRootPath = DEFAULT_PATH;
			String coapRootPath = DEFAULT_PATH;

			switch (args.length) {
			case 2:
				coapRootPath = args[1];
				if (0 <= coapRootPath.indexOf('/')) {
					LOG.error("{} don't use '/'! Only one path segement for coap root allowed!",
							coapRootPath);
					return;
				}
			case 1:
				filesRootPath = args[0];
				break;
			}

			File filesRoot = new File(filesRootPath);
			if (!filesRoot.exists()) {
				LOG.error("{} doesn't exists!", filesRoot.getAbsolutePath());
				return;
			} else if (!filesRoot.isDirectory()) {
				LOG.error("{} is no directory!", filesRoot.getAbsolutePath());
				return;
			}

			File[] files = filesRoot.listFiles();
			for (File file : files) {
				if (file.isFile() && file.canRead()) {
					LOG.info("GET: coap://<host>/{}/{}", new Object[] { coapRootPath, file.getName() });
					break;
				}
			}
			// create server
			SimpleFileServer server = new SimpleFileServer(coapRootPath, filesRoot);
			// add endpoints on all IP addresses
			server.addEndpoints();
			server.start();

		} catch (SocketException e) {
			LOG.error("Failed to initialize server: ", e);
		}
	}

	/**
	 * Add individual endpoints listening on default CoAP port on all IPv4
	 * addresses of all network interfaces.
	 */
	private void addEndpoints() {
		for (InetAddress addr : EndpointManager.getEndpointManager().getNetworkInterfaces()) {
			CoapEndpoint.CoapEndpointBuilder builder = new CoapEndpoint.CoapEndpointBuilder();
			builder.setInetSocketAddress(new InetSocketAddress(addr, COAP_PORT));
			addEndpoint(builder.build());
		}
	}

	/*
	 * Constructor for a new simple file server. Here, the resources of the
	 * server are initialized.
	 */
	public SimpleFileServer(String coapRootPath, File filesRoot) throws SocketException {
		add(new FileResource(coapRootPath, filesRoot));
	}

	class FileResource extends CoapResource {
		/**
		 * Files root directory.
		 */
		private final File filesRoot;

		/**
		 * Create CoAP file resource.
		 * 
		 * @param coapRootPath
		 *            CoAP resource (base) name
		 * @param fileRootPath
		 *            path to file root
		 * @param maxFileLength
		 *            maximum file length
		 */
		public FileResource(String coapRootPath, File filesRoot) {
			super(coapRootPath);
			this.filesRoot = filesRoot;
		}

		/*
		 * Override the default behavior so that requests to sub resources
		 * (typically /{path}/{file-name}) are handled by /file resource.
		 */
		@Override
		public Resource getChild(String name) {
			return this;
		}

		@Override
		public void handleRequest(Exchange exchange) {
			try {
				super.handleRequest(exchange);
			} catch (Exception e) {
				LOG.error("Exception while handling a request on the {} resource", getName(), e);
				exchange.sendResponse(new Response(CoAP.ResponseCode.INTERNAL_SERVER_ERROR));
			}
		}

		@Override
		public void handleGET(final CoapExchange exchange) {
			Request request = exchange.advanced().getRequest();
			LOG.info("Get received : {}", request);

			int accept = request.getOptions().getAccept();
			if (MediaTypeRegistry.UNDEFINED == accept) {
				accept = MediaTypeRegistry.APPLICATION_OCTET_STREAM;
			} else if (MediaTypeRegistry.APPLICATION_OCTET_STREAM != accept) {
				exchange.respond(CoAP.ResponseCode.UNSUPPORTED_CONTENT_FORMAT);
				return;
			}

			String myURI = getURI() + "/";
			String path = "/" + request.getOptions().getUriPathString();
			if (!path.startsWith(myURI)) {
				LOG.info("Request {} does not match {}!", new Object[] { path, myURI });
				exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR);
				return;
			}
			path = path.substring(myURI.length());
			if (request.getOptions().hasBlock2()) {
				LOG.info("Send file {} {}", new Object[] { path, request.getOptions().getBlock2() });
			} else {
				LOG.info("Send file {}", path);
			}
			File file = new File(filesRoot, path);
			if (!file.exists() || !file.isFile()) {
				LOG.warn("File {} doesn't exist!", file.getAbsolutePath());
				exchange.respond(CoAP.ResponseCode.NOT_FOUND);
				return;
			}
			if (!checkFileLocation(file, filesRoot)) {
				LOG.warn("File {} is not in {}!",
						new Object[] { file.getAbsolutePath(), filesRoot.getAbsolutePath() });
				exchange.respond(CoAP.ResponseCode.UNAUTHORIZED);
				return;
			}

			if (!file.canRead()) {
				LOG.warn("File {} is not readable!", file.getAbsolutePath());
				exchange.respond(CoAP.ResponseCode.UNAUTHORIZED);
				return;
			}
			long maxLength = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE);
			long length = file.length();
			if (length > maxLength) {
				LOG.warn("File {} is too large {} (max.: {})!",
						new Object[] { file.getAbsolutePath(), length, maxLength });
				exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR);
				return;
			}
			try (InputStream in = new FileInputStream(file)) {
				byte[] content = new byte[(int) length];
				int r = in.read(content);
				if (length == r) {
					Response response = new Response(CoAP.ResponseCode.CONTENT);
					response.setPayload(content);
					response.getOptions().setSize2((int) length);
					response.getOptions().setContentFormat(accept);
					exchange.respond(response);
				} else {
					LOG.warn("File {} could not be read in!", file.getAbsolutePath());
					exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR);
				}
			} catch (IOException ex) {
				LOG.warn("File {}:", file.getAbsolutePath(), ex);
				exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR);
			}
		}

		/**
		 * Check, if file is located in root.
		 * 
		 * Detect attacks via "../.../../file".
		 * 
		 * @param file
		 *            file to check
		 * @param root
		 *            file root
		 * @return true, if file is locate in root (or a sub-folder of root),
		 *         false, otherwise.
		 */
		private boolean checkFileLocation(File file, File root) {
			try {
				return file.getCanonicalPath().startsWith(root.getCanonicalPath());
			} catch (IOException ex) {
				LOG.warn("File {0}:", file.getAbsolutePath(), ex);
				return false;
			}
		}
	}

}
