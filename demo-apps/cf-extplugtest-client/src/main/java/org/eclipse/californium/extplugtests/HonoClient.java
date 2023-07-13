/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.extplugtests;

import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.cli.ClientConfig;
import org.eclipse.californium.cli.ClientConfig.ContentType;
import org.eclipse.californium.cli.ClientConfig.Payload;
import org.eclipse.californium.cli.ClientInitializer;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.EndpointContextTracer;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.scandium.config.DtlsConfig;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

public class HonoClient {

	private static final String DEFAULT_HONO = "hono.eclipseprojects.io";
	private static final File CONFIG_FILE = new File("CaliforniumHono3.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Hono Client";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	private static final int DEFAULT_BLOCK_SIZE = 1024;

	@Command(name = "HonoClient", version = "(c) 2020, Bosch.IO GmbH and others.",
			footer = {
					"",
					"text payload: format is applied to the text payload with",
					"              a random number [0..100) as 1. parameter,",
					"              a timestamp of seconds since 1.1.1970 as 2.,",
					"              and a correlation-id string as 3. parameter.",
					"",
					"Example:",
					"  HonoClient coaps://" + DEFAULT_HONO + "/telemetry --json \\",
					"     --payload \"{\"temp\": %%d}\" --payloadFormat",
					"  (Send a temperature in json as telemetry, %%d is replaced by a random number)",
			})
	private static class Config extends ClientConfig {

		@Option(names = "--requests", defaultValue = "2", description = "number of requests. Default ${DEFAULT-VALUE}.")
		public int requests;

		@Option(names = "--mode", defaultValue = "0", description = "precompiled payload. Default ${DEFAULT-VALUE}.")
		public int mode;

		@Option(names = { "-r", "--responses-directory" }, description = "directory to store responses.")
		public String responses;

	}

	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.MAX_ACTIVE_PEERS, 10);
			config.set(CoapConfig.MAX_PEER_INACTIVITY_PERIOD, 24, TimeUnit.HOURS);
			config.set(TcpConfig.TCP_CONNECTION_IDLE_TIMEOUT, 12, TimeUnit.HOURS);
			config.set(TcpConfig.TCP_CONNECT_TIMEOUT, 30, TimeUnit.SECONDS);
			config.set(TcpConfig.TLS_HANDSHAKE_TIMEOUT, 30, TimeUnit.SECONDS);
			config.set(TcpConfig.TCP_WORKER_THREADS, 1);
			config.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 1);
			config.set(DtlsConfig.DTLS_MAX_CONNECTIONS, 10);
			config.set(DtlsConfig.DTLS_MAX_RETRANSMISSIONS, 2);
			config.set(DtlsConfig.DTLS_AUTO_HANDSHAKE_TIMEOUT, null, TimeUnit.SECONDS);
			config.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 0); // support it, but don't use it
			config.set(DtlsConfig.DTLS_RECEIVE_BUFFER_SIZE, 8192);
			config.set(DtlsConfig.DTLS_SEND_BUFFER_SIZE, 8192);
			config.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, false);
			config.set(UdpConfig.UDP_RECEIVER_THREAD_COUNT, 1);
			config.set(UdpConfig.UDP_SENDER_THREAD_COUNT, 1);
			config.set(CoapConfig.PROTOCOL_STAGE_THREAD_COUNT, 1);
		}
	};

	private static void applyPayload(int mode, Request request) {
		switch (mode) {
		case 3:
			request.getOptions().setContentFormat(APPLICATION_JSON);
			request.setPayload(
					"[{\n" + 
					"  \"topic\": \"${thing}/things/twin/commands/modify\",\n" + 
					"  \"headers\": {\n" +
					"    \"response-required\": false\n" +
					"  },\n" + 
					"  \"path\": \"/features/temperature/properties\",\n" + 
					"  \"value\": {\n" + 
					"    \"status\": {\n" + 
					"      \"value\": {\n" + 
					"        \"currentMeasured\": %1$d\n" + 
					"      }\n" + 
					"    }\n" + 
					"  }\n" + 
					"},{\n" + 
					"  \"topic\": \"${thing}/things/twin/commands/retrieve\",\n" + 
					"  \"headers\": {\n" +
					"    \"reply-to\": \"command/tpostmanserviceinstance\",\n" +
					"    \"correlation-id\": \"%3$s\"\n" +
					"  },\n" + 
					"  \"path\": \"/features/temperature/properties\",\n" + 
					"  \"value\": {}\n" +
					"  }\n" + 
					"]\n");
			break;
		case 2:
			request.getOptions().setContentFormat(APPLICATION_JSON);
			request.setPayload(
					"{\n" + 
					"  \"topic\": \"${thing}/things/twin/commands/retrieve\",\n" + 
					"  \"headers\": {\n" +
					"    \"reply-to\": \"command/tpostmanserviceinstance\",\n" +
					"    \"correlation-id\": \"%1$d-%3$s\"\n" +
					"  },\n" + 
					"  \"path\": \"/features/temperature/properties\",\n" + 
					"  \"value\": {}\n" + 
					"}\n");
			break;
		case 1:
			request.getOptions().setContentFormat(APPLICATION_JSON);
			request.setPayload(
					"{\n" + 
					"  \"topic\": \"com.coap.pg/coap-1/things/twin/commands/modify\",\n" + 
					"  \"headers\": {\n" +
					"    \"response-required\": false\n" +
					"  },\n" + 
					"  \"path\": \"/features/temperature/properties\",\n" + 
					"  \"value\": {\n" + 
					"    \"status\": {\n" + 
					"      \"value\": {\n" + 
					"        \"currentMeasured\": %1$d\n" + 
					"      }\n" + 
					"    }\n" + 
					"  }\n" + 
					"}\n");
			break;
		case 0:
		default:
			request.getOptions().setContentFormat(TEXT_PLAIN);
			request.setPayload(
					"temperature|%2$d\n" + 
					"currentMeasured:%1$d\n" + 
					"minMeasured:-5\n" + 
					"maxMeasured:124\n" + 
					".");
			break;
		}
	}

	private static byte[] formatPayload(Config config, int value, CorrelationId id) {
		if (config.payloadFormat) {
			String text = config.payload.text;
			if (text == null) {
				text = new String(config.payload.payloadBytes, CoAP.UTF8_CHARSET);
			}
			return String.format(text, value, System.currentTimeMillis() / 1000, id).getBytes();
		} else {
			return config.payload.payloadBytes;
		}
	}

	/**
	 * Main entry point.
	 * 
	 * @param args the arguments
	 * @throws IOException
	 * @throws ConnectorException
	 */
	public static void main(String[] args) throws IOException, ConnectorException {
		// hono sandbox
		TcpConfig.register();
		final Config clientConfig = new Config();
		clientConfig.setDefaultPskCredentials("sensor1@DEFAULT_TENANT", "hono-secret");
		clientConfig.defaultUri = "coaps://" + DEFAULT_HONO + "/telemetry";
		clientConfig.configurationHeader = CONFIG_HEADER;
		clientConfig.customConfigurationDefaultsProvider = DEFAULTS;
		clientConfig.configurationFile = CONFIG_FILE;
		ClientInitializer.init(args, clientConfig);
		if (clientConfig.helpRequested) {
			System.exit(0);
		}

		Random rand = new Random();
		CorrelationId id = new CorrelationId(rand);
		if (clientConfig.identity == null) {
			System.out.println("> " + clientConfig.uri);
		} else {
			System.out.println("> " + clientConfig.identity + ", " + clientConfig.uri);
		}
		CoapClient client = new CoapClient(clientConfig.uri);
		CoAP.Code code = clientConfig.method == null ? Code.POST : clientConfig.method;
		final Request request = new Request(code);
		if (clientConfig.messageType != null) {
			request.setConfirmable(clientConfig.messageType.con);
		}
		if (clientConfig.contentType == null) {
			clientConfig.contentType = new ContentType();
			clientConfig.contentType.contentType = MediaTypeRegistry.TEXT_PLAIN;
		}

		if (clientConfig.payload == null && request.isIntendedPayload()) {
			applyPayload(clientConfig.mode, request);
			clientConfig.payload = new Payload();
			clientConfig.payload.text = request.getPayloadString();
			clientConfig.payloadFormat = true;
			clientConfig.contentType.contentType = request.getOptions().getContentFormat();
		}

		request.getOptions().setAccept(clientConfig.contentType.contentType);
		request.getOptions().setContentFormat(clientConfig.contentType.contentType);
		request.setPayload(formatPayload(clientConfig, rand.nextInt(100), id));
		request.setURI(clientConfig.uri);
		request.addMessageObserver(new EndpointContextTracer() {

			@Override
			public void onReadyToSend() {
				System.out.println(Utils.prettyPrint(request));
				System.out.println();
			}

			@Override
			public void onAcknowledgement() {
				System.out.println(">>> ACK <<<");
			}

			@Override
			public void onDtlsRetransmission(int flight) {
				System.out.println(">>> DTLS retransmission, flight " + flight);
			}

			@Override
			protected void onContextChanged(EndpointContext endpointContext) {
				System.out.println(Utils.prettyPrint(endpointContext));
			}
		});

		long start = System.nanoTime();
		List<Long> rtt = new ArrayList<Long>(clientConfig.requests);
		CoapResponse coapResponse = exchange(clientConfig, client, request, true);
		if (coapResponse != null && getCommand(coapResponse) == null) {
			rtt.add(coapResponse.advanced().getApplicationRttNanos());
			Request followUpRequests = null;
			for (int index = 1; index < clientConfig.requests; ++index) {
				followUpRequests = new Request(code);
				followUpRequests.getOptions().setAccept(clientConfig.contentType.contentType);
				followUpRequests.getOptions().setContentFormat(clientConfig.contentType.contentType);
				id.next();
				followUpRequests.setPayload(formatPayload(clientConfig, rand.nextInt(100), id));
				followUpRequests.setURI(clientConfig.uri);
				coapResponse = exchange(clientConfig, client, followUpRequests, true);
				if (coapResponse == null) { 
					System.out.format("Stale at %d.%n", index);
					break;
				} else if (!coapResponse.isSuccess()) {
					if (coapResponse.getCode() == ResponseCode.SERVICE_UNAVAILABLE) {
						long age = coapResponse.advanced().getOptions().getMaxAge();
						long delay = TimeUnit.SECONDS.toMillis(age < 2 ? 2 : age);
						try {
							Thread.sleep(delay);
						} catch (InterruptedException e) {
						}
					}
				}
				rtt.add(coapResponse.advanced().getApplicationRttNanos());
			}
			start = System.nanoTime() - start;
			if (followUpRequests != null && coapResponse != null) {
				System.out.println();
				System.out.println(Utils.prettyPrint(followUpRequests));
				System.out.println();
				System.out.println(Utils.prettyPrint(coapResponse));
			}
			int count = 0;
			int overtimeCount = 0;
			long average = 0;
			long overtime = 0;
			for (int index = 0; index < rtt.size(); ++index) {
				Long time = rtt.get(index);
				if (time != null) {
					++count;
					long millis = TimeUnit.NANOSECONDS.toMillis(time);
					System.out.format("RTT[%d] : %d ms %n", index, millis);
					if (500 < millis) {
						++overtimeCount;
						overtime += millis;
					}
					average += millis;
				}
			}
			System.out.format("Overall time: %d [ms] %n", TimeUnit.NANOSECONDS.toMillis(start));
			if (0 < count) {
				System.out.format("Average time: %d [ms] %n", average / count);
				if (0 < overtimeCount) {
					System.out.format("Overtime    : %d, %d [ms], avg %d [ms] %n", overtimeCount, overtime,
							overtime / overtimeCount);
				}
			}
		}
	}

	private static File file;

	private static CoapResponse exchange(Config clientConfig, CoapClient client, Request request, boolean verbose)
			throws ConnectorException, IOException {
		CoapResponse coapResponse = client.advanced(request);

		if (coapResponse != null) {
			if (verbose) {
				System.out.println();
				System.out.println(Utils.prettyPrint(coapResponse));
			}

			String cmd = getCommand(coapResponse);

			if (cmd != null) {
				if (clientConfig.responses != null) {
					FileOutputStream out;
					if (file == null) {
						File dir = new File(clientConfig.responses);
						if (!dir.exists()) {
							dir.mkdirs();
						}
						if (dir.isDirectory()) {
							String name = String.format("response-%1$tj-%1$tT-%2$s", Calendar.getInstance(), coapResponse.advanced().getTokenString());
							file = new File(clientConfig.responses, name);
							out = new FileOutputStream(file);
						} else {
							System.err.println(dir + " is not a directory!");
							return null;
						}
					} else {
						out = new FileOutputStream(file, true);
					}

					byte[] download = coapResponse.getPayload();
					out.write(download, 8, download.length - 8);
					out.close();
				}
				List<String> location = coapResponse.getOptions().getLocationPath();
				if (location.size() == 2 || location.size() == 4) {
					System.out.println("cmd: " + cmd + ", " + location);
					final Request cmdResponse = new Request(request.getCode());
					URI uri = URI.create(request.getURI());
					try {
						uri = new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), null, "hono-cmd-status=200",
								null);
						cmdResponse.setURI(uri);
						cmdResponse.getOptions().getUriPath().addAll(location);
						cmdResponse.addMessageObserver(new MessageObserverAdapter() {

							@Override
							public void onReadyToSend() {
								System.out.println(Utils.prettyPrint(cmdResponse));
								System.out.println();
							}
						});
						cmdResponse.setPayload("OK");
						coapResponse = client.advanced(cmdResponse);
						System.out.println(Utils.prettyPrint(coapResponse));
					} catch (URISyntaxException e) {
						System.out.println("c&c:" + e.getMessage());
					}
				} else {
					System.out.println("cmd: " + cmd);
				}
			}
		} else {
			System.out.println("No response received.");
		}

		return coapResponse;
	}

	private static String getCommand(CoapResponse coapResponse) {
		String cmd = null;
		List<String> queries = coapResponse.getOptions().getLocationQuery();
		for (String query : queries) {
			if (query.startsWith("hono-command=")) {
				cmd = query.substring("hono-command=".length());
				break;
			}
		}
		return cmd;
	}

	private static class CorrelationId {
		private static final int MAX = 1000000;
		private String id1;
		private int id2;

		private CorrelationId(Random rand) {
			this.id1 = String.format("%06d", rand.nextInt(MAX));
			this.id2 = rand.nextInt(MAX);
			next();
		}

		private void next() {
			++id2;
			if (id2 < 0 || MAX <= id2) {
				id2 = 0;
			}
		}

		public String toString() {
			return String.format("%s-%06d", id1, id2);
		}
	}
}
