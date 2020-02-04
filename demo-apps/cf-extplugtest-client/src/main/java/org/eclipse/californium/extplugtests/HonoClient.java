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
 *    Bosch IO GmbH - derived from org.eclipse.californium.proxy
 ******************************************************************************/
package org.eclipse.californium.extplugtests;

import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;

import java.io.File;
import java.io.IOException;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.plugtests.ClientInitializer;
import org.eclipse.californium.plugtests.ClientInitializer.Arguments;

public class HonoClient {

	private static final File CONFIG_FILE = new File("CaliforniumHono.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Hono Client";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	private static final int DEFAULT_BLOCK_SIZE = 1024;

	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.MAX_ACTIVE_PEERS, 10);
			config.setInt(Keys.MAX_PEER_INACTIVITY_PERIOD, 60 * 60 * 24); // 24h
			config.setInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT, 60 * 60 * 12); // 12h
			config.setInt(Keys.TCP_CONNECT_TIMEOUT, 20);
			config.setInt(Keys.TCP_WORKER_THREADS, 2);
		}
	};

	/**
	 * Main entry point.
	 * 
	 * @param args the arguments
	 * @throws IOException 
	 * @throws ConnectorException 
	 */
	public static void main(String[] args) throws IOException, ConnectorException {

		if (args.length == 0) {

			System.out.println("\nCalifornium (Cf) Hono Client");
			System.out.println("(c) 2020, Bosch IO GmbH and others");
			System.out.println();
			System.out.println(
					"Usage: " + HonoClient.class.getSimpleName() + " [-v] [-r|-x|-i id pw] URI [payload] [PUT|POST]");
			System.out.println("  -v        : verbose. Enable message tracing.");
			System.out.println("  -r        : use raw public certificate. Default PSK.");
			System.out.println("  -i id pw  : use PSK with id and password");
			System.out.println("  -x        : use x.509 certificate");
			System.out.println(
					"  URI       : The CoAP URI of the extended Plugtest server to test (coap://<host>[:<port>]/path)");
			System.out.println("  payload   : payload to send. Default \"{\"temp\": 7}\"");
			System.out.println("  method    : method to send. Default \"POST\"");
			System.out.println("  type      : type to send. Default \"CON\"");
			System.out.println();
			System.out.println("Example: " + HonoClient.class.getSimpleName()
					+ " coaps://hono.eclipseprojects.io:30683/telemetry \"{\"temp\": 7}\"");
			System.out.println("         (currently 01-2020, the hono sandbox doesn't provide the coap-adapter!)");
			System.exit(-1);
		}

		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		Arguments arguments = ClientInitializer.init(config, args, true);
		String payload = "{\"temp\": %d}";
		String method = "POST";
		String type = "CON";
		if (0 < arguments.args.length) {
			payload = arguments.args[0];
			System.out.println("> " + payload);
			if (1 < arguments.args.length) {
				method = arguments.args[1];
				System.out.println("> " + method);
				if (2 < arguments.args.length) {
					type = arguments.args[2];
					System.out.println("> " + type);
				}
			}
		}

		Random rand = new Random();
		System.out.println("> " + arguments.uri);
		CoapClient client = new CoapClient(arguments.uri);
		final Request request = (method.equalsIgnoreCase("PUT")) ? Request.newPut() : Request.newPost();
		request.setConfirmable(type.equalsIgnoreCase("CON"));
		request.getOptions().setAccept(APPLICATION_JSON);
		request.getOptions().setContentFormat(APPLICATION_JSON);
		request.setPayload(String.format(payload, rand.nextInt(100)));
		request.setURI(arguments.uri);
		request.addMessageObserver(new MessageObserverAdapter() {

			@Override
			public void onReadyToSend() {
				System.out.println(Utils.prettyPrint(request));
				System.out.println();
			}
		});
		CoapResponse coapResponse = client.advanced(request);

		if (coapResponse != null) {
			System.out.println(coapResponse.getCode());
			System.out.println(coapResponse.getOptions());
			System.out.println();
			System.out.println(Utils.prettyPrint(coapResponse));
			if (coapResponse.isSuccess()) {
				Request requests = null;
				for (int index = 0; index < 200; ++index) {
					requests = (method.equalsIgnoreCase("PUT")) ? Request.newPut() : Request.newPost();
					requests.getOptions().setAccept(APPLICATION_JSON);
					requests.getOptions().setContentFormat(APPLICATION_JSON);
					requests.setPayload(String.format(payload, rand.nextInt(100)));
					requests.setURI(arguments.uri);
					coapResponse = client.advanced(requests);
					if (coapResponse == null) {
						System.out.format("Stale at %d.%n", index);
						break;
					} else if (!coapResponse.isSuccess()){
						if (coapResponse.getCode() == ResponseCode.SERVICE_UNAVAILABLE) {
							long age = coapResponse.advanced().getOptions().getMaxAge();
							long delay = TimeUnit.SECONDS.toMillis(age < 2 ? 2 : age);
							try {
								Thread.sleep(delay);
							} catch (InterruptedException e) {
							}
						}
					}
				}
				if (coapResponse != null) {
					System.out.println();
					System.out.println(Utils.prettyPrint(requests));
					System.out.println();
					System.out.println(Utils.prettyPrint(coapResponse));
				}
			}
		} else {
			System.out.println("No response received.");
		}
	}
}
