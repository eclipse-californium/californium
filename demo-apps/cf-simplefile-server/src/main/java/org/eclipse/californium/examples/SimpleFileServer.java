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
 *    Bosch Software Innovations GmbH - initial creation
 *                                      derived from HelloWorldServer example
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.ParseResult;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.plugtests.AbstractTestServer;
import org.eclipse.californium.plugtests.PlugtestServer.BaseConfig;

public class SimpleFileServer extends AbstractTestServer {

	private static final Logger LOG = LoggerFactory.getLogger(SimpleFileServer.class);

	private static final File CONFIG_FILE = new File("Californium.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Fileserver";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 2 * 1024 * 1024; // 2 MB
	private static final int DEFAULT_BLOCK_SIZE = 512;

	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
		}
	};

	private static final String DEFAULT_PATH = "data";

	@Command(name = "SimpleFileServer", version = "(c) 2017, Bosch Software Innovations GmbH and others.")
	public static class Config extends BaseConfig {

	}

	private static final Config config = new Config();

	/*
	 * Application entry point.
	 */
	public static void main(String[] args) {
		CommandLine cmd = new CommandLine(config);
		try {
			ParseResult result = cmd.parseArgs(args);
			if (result.isVersionHelpRequested()) {
				String version = StringUtil.CALIFORNIUM_VERSION == null ? "" : StringUtil.CALIFORNIUM_VERSION;
				System.out.println("\nCalifornium (Cf) " + cmd.getCommandName() + " " + version);
				cmd.printVersionHelp(System.out);
				System.out.println();
			}
			if (result.isUsageHelpRequested()) {
				cmd.usage(System.out);
				return;
			}
		} catch (ParameterException ex) {
			System.err.println(ex.getMessage());
			System.err.println();
			cmd.usage(System.err);
			System.exit(-1);
		}

		NetworkConfig netConfig = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		NetworkConfig udpConfig = new NetworkConfig(netConfig);
		udpConfig.setInt(Keys.MAX_MESSAGE_SIZE, 64);
		udpConfig.setInt(Keys.PREFERRED_BLOCK_SIZE, 64);
		Map<Select, NetworkConfig> protocolConfig = new HashMap<>();
		protocolConfig.put(new Select(Protocol.UDP, InterfaceType.EXTERNAL), udpConfig);

		try {
			String filesRootPath = DEFAULT_PATH;
			String coapRootPath = DEFAULT_PATH;

			switch (args.length) {
			case 2:
				coapRootPath = args[1];
				if (0 <= coapRootPath.indexOf('/')) {
					LOG.error("{} don't use '/'! Only one path segement for coap root allowed!", coapRootPath);
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
					LOG.info("GET: coap://<host>/{}/{}", coapRootPath, file.getName());
					break;
				}
			}
			// create server
			SimpleFileServer server = new SimpleFileServer(netConfig, protocolConfig, coapRootPath, filesRoot);
			// add endpoints on all IP addresses
			server.addEndpoints(null, null, Arrays.asList(Protocol.UDP, Protocol.DTLS, Protocol.TCP, Protocol.TLS), config);
			server.start();

		} catch (SocketException e) {
			LOG.error("Failed to initialize server: ", e);
		}
	}

	/*
	 * Constructor for a new simple file server. Here, the resources of the
	 * server are initialized.
	 */
	public SimpleFileServer(NetworkConfig config, Map<Select, NetworkConfig> protocolConfig, String coapRootPath, File filesRoot) throws SocketException {
		super(config, protocolConfig);
		add(new FileResource(config, coapRootPath, filesRoot));
	}

	class FileResource extends CoapResource {

		private final NetworkConfig config;
		/**
		 * Files root directory.
		 */
		private final File filesRoot;

		/**
		 * Create CoAP file resource.
		 * 
		 * @param config network configuration
		 * @param coapRootPath CoAP resource (base) name
		 * @param filesRoot files root
		 * @param maxFileLength maximum file length
		 */
		public FileResource(NetworkConfig config, String coapRootPath, File filesRoot) {
			super(coapRootPath);
			this.config = config;
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
				LOG.info("Request {} does not match {}!", path, myURI);
				exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR);
				return;
			}
			path = path.substring(myURI.length());
			if (request.getOptions().hasBlock2()) {
				LOG.info("Send file {} {}", path, request.getOptions().getBlock2());
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
				LOG.warn("File {} is not in {}!", file.getAbsolutePath(), filesRoot.getAbsolutePath());
				exchange.respond(CoAP.ResponseCode.UNAUTHORIZED);
				return;
			}

			if (!file.canRead()) {
				LOG.warn("File {} is not readable!", file.getAbsolutePath());
				exchange.respond(CoAP.ResponseCode.UNAUTHORIZED);
				return;
			}
			long maxLength = config.getInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE);
			long length = file.length();
			if (length > maxLength) {
				LOG.warn("File {} is too large {} (max.: {})!", file.getAbsolutePath(), length, maxLength);
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
		 * @param file file to check
		 * @param root file root
		 * @return true, if file is locate in root (or a sub-folder of root),
		 *         false, otherwise.
		 */
		private boolean checkFileLocation(File file, File root) {
			try {
				return file.getCanonicalPath().startsWith(root.getCanonicalPath());
			} catch (IOException ex) {
				LOG.warn("File {}:", file.getAbsolutePath(), ex);
				return false;
			}
		}
	}
}
