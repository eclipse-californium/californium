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
 *    Bosch Software Innovations GmbH - initial implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use special properties file
 *                                                    for configuration
 ******************************************************************************/

package org.eclipse.californium.extplugtests;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CHANGED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_CBOR;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.BindException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.SimpleDateFormat;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.cli.ClientConfig;
import org.eclipse.californium.cli.ClientInitializer;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.EndpointContextTracer;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.StringUtil;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * The RecevietestClient uses the developer API of Californium to test the
 * communication. The server side keeps track of the last received request and
 * response with that history. So if a request fails, the nest request may show,
 * if the request was lost (not in history) or only the response was lost.
 */
public class ReceivetestClient {

	private static final File CONFIG_FILE = new File("CaliforniumReceivetest.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Receivetest Client";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	private static final int DEFAULT_BLOCK_SIZE = 1024;

	private static final int RESPONSE_HEADER_SIZE = 16;

	/**
	 * Properties filename for device UUID.
	 */
	private static final String UUID_FILE = "UUID.properties";
	/**
	 * Properties key for device UUID.
	 */
	private static final String UUID_KEY = "UUID";
	/**
	 * Prefix for request ID.
	 */
	private static final String REQUEST_ID_PREFIX = "RID";

	/**
	 * Maximum time difference display as milliseconds.
	 */
	private static final int MAX_DIFF_TIME_IN_MILLIS = 30000;

	@Command(name = "ReceivetestClient", version = "(c) 2018-2020, Bosch.IO GmbH and others.")
	private static class Config extends ClientConfig {

		@Option(names = "--reset-uuid", description = "reset UUID.")
		public boolean resetUuid;

	}

	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.MAX_ACTIVE_PEERS, 10);
		}
	};

	/**
	 * Main entry point.
	 * 
	 * @param args the arguments
	 */
	public static void main(String[] args) throws ConnectorException, IOException {

		final Config clientConfig = new Config();
		clientConfig.networkConfigHeader = CONFIG_HEADER;
		clientConfig.networkConfigDefaultHandler = DEFAULTS;
		clientConfig.networkConfigFile = CONFIG_FILE;

		try {
			ClientInitializer.init(args, clientConfig);
		} catch (BindException ex) {
			if (clientConfig.localPort != null) {
				int port = clientConfig.localPort;
				clientConfig.localPort = null;
				ClientInitializer.init(args, clientConfig);
				System.out.println("Port " + port + " not available, use ephemeral port!");
			} else {
				throw ex;
			}
		}
		if (clientConfig.helpRequested) {
			System.out.println(
					"Example: " + ReceivetestClient.class.getSimpleName() + " coap://californium.eclipseprojects.io:5783");
			System.exit(0);
		}

		String uuid = getUUID(clientConfig.resetUuid);
		String uri = null;
		String query = null;
		try {
			URI aUri = new URI(clientConfig.uri);
			String host = aUri.getHost();
			String scheme = aUri.getScheme();
			int port = aUri.getPort();
			if (port < 0 && host.equals(Config.DEFAULT_URI)) {
				// receive test is hosted on extend-plugtest-server
				port = CoAP.isSecureScheme(scheme) ? 5784 : 5783;
			}
			query = aUri.getQuery();
			aUri = new URI(scheme, null, host, port, null, null, null);
			uri = aUri.toASCIIString();
		} catch (URISyntaxException e) {
			System.err.println("URI error: " + e.getMessage());
			System.exit(-1);
		}
		CoapClient client = new CoapClient(uri);
		final AtomicInteger receivedData = new AtomicInteger();
		final Request request = Request.newPost();
		if (clientConfig.contentType != null) {
			request.getOptions().setAccept(clientConfig.contentType.contentType);
		}
		if (clientConfig.recordSizeLimit != null) {
			if (query == null || query.isEmpty()) {
				query = "rlen=" + (clientConfig.recordSizeLimit - RESPONSE_HEADER_SIZE);
			} else if (!query.contains("rlen=")) {
				query += "&rlen=" + (clientConfig.recordSizeLimit - RESPONSE_HEADER_SIZE);
			}
		}
		if (query == null || query.isEmpty()) {
			query = "";
		} else {
			System.out.println("extra: " + query);
			query = "&" + query;
		}
		request.setURI(uri + "/requests?dev=" + uuid + "&rid=" + REQUEST_ID_PREFIX + System.currentTimeMillis() + "&ep"
				+ query);
		if (clientConfig.verbose) {
			request.addMessageObserver(new EndpointContextTracer() {

				@Override
				public void onResponse(final Response response) {
					byte[] raw = response.getBytes();
					if (raw != null) {
						receivedData.addAndGet(raw.length);
					}
				}

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
		}
		CoapResponse coapResponse = client.advanced(request);

		if (coapResponse != null) {
			ResponseCode code = coapResponse.getCode();
			int format = coapResponse.getOptions().getContentFormat();
			if ((CONTENT == code || CHANGED == code) && format == APPLICATION_JSON) {
				// JSON success
				Response response = coapResponse.advanced();
				printHead(response);
				String statistic = processJSON(response.getPayloadString(), "", clientConfig.verbose);
				System.out.println(statistic);
			} else if ((CONTENT == code || CHANGED == code) && format == APPLICATION_CBOR) {
				// CBOR success
				Response response = coapResponse.advanced();
				printHead(response);
				String statistic = processCBOR(response.getPayload(), "", clientConfig.verbose);
				System.out.println(statistic);
			} else {
				System.out.println(coapResponse.getCode());
				System.out.println(coapResponse.getOptions());
				System.out.println(System.lineSeparator() + "ADVANCED" + System.lineSeparator());
				System.out.println(Utils.prettyPrint(coapResponse));
			}
		} else {
			System.out.println("No response received.");
		}
		client.shutdown();
		System.exit(0);
	}

	private static void printHead(Response response) {
		System.out.println();
		byte[] raw = response.getBytes();
		if (raw == null) {
			System.out.println("Response: Payload: " + response.getPayloadSize() + " bytes");
		} else {
			System.out.println("Response: " + raw.length + " bytes, Payload: " + response.getPayloadSize() + " bytes");
		}
		Long rtt = response.getRTT();
		if (rtt != null) {
			System.out.println("RTT: " + rtt + "ms");
		}
		System.out.println();
	}

	/**
	 * Process JSON response.
	 * 
	 * @param payload JSON payload as string
	 * @param errors request ID of previously failed request.
	 * @param verbose {@code true} to interpret the string, either pretty JSON,
	 *            or pretty application, if data complies the assumed request
	 *            statistic information.
	 * @return payload as application text, pretty JSON, or just as provided
	 *         text.
	 */
	public static String processJSON(String payload, String errors, boolean verbose) {
		StringBuilder statistic = new StringBuilder();
		JsonElement element = null;
		try {
			JsonParser parser = new JsonParser();
			element = parser.parse(payload);

			if (verbose && element.isJsonArray()) {
				// expected JSON data
				SimpleDateFormat format = new SimpleDateFormat("HH:mm:ss dd.MM.yyyy");
				try {
					for (JsonElement item : element.getAsJsonArray()) {
						if (!item.isJsonObject()) {
							// unexpected =>
							// stop application pretty printing
							statistic.setLength(0);
							break;
						}
						JsonObject object = item.getAsJsonObject();
						if (object.has("rid")) {
							String rid = object.get("rid").getAsString();
							long time = object.get("time").getAsLong();
							if (rid.startsWith(REQUEST_ID_PREFIX)) {
								boolean hit = errors.contains(rid);
								rid = rid.substring(REQUEST_ID_PREFIX.length());
								long requestTime = Long.parseLong(rid);
								statistic.append("Request: ").append(format.format(requestTime));
								long diff = time - requestTime;
								if (-MAX_DIFF_TIME_IN_MILLIS < diff && diff < MAX_DIFF_TIME_IN_MILLIS) {
									statistic.append(", received: ").append(diff).append(" ms");
								} else {
									statistic.append(", received: ").append(format.format(time));
								}
								if (hit) {
									statistic.append(" * lost response!");
								}
							} else {
								statistic.append("Request: ").append(rid);
								statistic.append(", received: ").append(format.format(time));
							}
							if (object.has("ep")) {
								String endpoint = object.get("ep").getAsString();
								if (endpoint.contains(":")) {
									endpoint = "[" + endpoint + "]";
								}
								int port = object.get("port").getAsInt();
								statistic.append(System.lineSeparator());
								statistic.append("    (").append(endpoint).append(":").append(port).append(")");
							}
							statistic.append(System.lineSeparator());
						} else {
							long time = object.get("systemstart").getAsLong();
							statistic.append("Server's system start: ").append(format.format(time));
							statistic.append(System.lineSeparator());
						}
					}
				} catch (Throwable e) {
					// unexpected => stop application pretty printing
					statistic.setLength(0);
				}
			}
			if (statistic.length() == 0) {
				// JSON plain pretty printing
				GsonBuilder builder = new GsonBuilder();
				builder.setPrettyPrinting();
				Gson gson = builder.create();
				gson.toJson(element, statistic);
			}
		} catch (JsonSyntaxException e) {
			// plain payload
			e.printStackTrace();
			statistic.setLength(0);
			statistic.append(payload);
		}
		return statistic.toString();
	}

	public static String processCBOR(byte[] payload, String errors, boolean verbose) {
		try {
			StringBuilder statistic = new StringBuilder();
			CBORObject element = CBORObject.DecodeFromBytes(payload);
			if (verbose && element.getType() == CBORType.Array) {
				// expected JSON data
				SimpleDateFormat format = new SimpleDateFormat("HH:mm:ss dd.MM.yyyy");
				try {
					for (CBORObject item : element.getValues()) {
						if (item.getType() != CBORType.Map) {
							// unexpected =>
							// stop application pretty printing
							statistic.setLength(0);
							break;
						}
						CBORObject value;
						if ((value = item.get("rid")) != null) {
							String rid = value.AsString();
							long time = item.get("time").AsInt64();
							if (rid.startsWith(REQUEST_ID_PREFIX)) {
								boolean hit = errors.contains(rid);
								rid = rid.substring(REQUEST_ID_PREFIX.length());
								long requestTime = Long.parseLong(rid);
								statistic.append("Request: ").append(format.format(requestTime));
								long diff = time - requestTime;
								if (-MAX_DIFF_TIME_IN_MILLIS < diff && diff < MAX_DIFF_TIME_IN_MILLIS) {
									statistic.append(", received: ").append(diff).append(" ms");
								} else {
									statistic.append(", received: ").append(format.format(time));
								}
								if (hit) {
									statistic.append(" * lost response!");
								}
							} else {
								statistic.append("Request: ").append(rid);
								statistic.append(", received: ").append(format.format(time));
							}
							if ((value = item.get("ep")) != null) {
								byte[] endpoint = value.GetByteString();
								int port = item.get("port").AsInt16() & 0xffff;
								statistic.append(System.lineSeparator());
								String address = InetAddress.getByAddress(endpoint).getHostAddress();
								if (address.contains(":")) {
									address = "[" + address + "]";
								}
								statistic.append("    (").append(address).append(":").append(port).append(")");
							}
							statistic.append(System.lineSeparator());
						} else {
							long time = item.get("systemstart").AsInt64();
							statistic.append("Server's system start: ").append(format.format(time));
							statistic.append(System.lineSeparator());
						}
					}
				} catch (Throwable e) {
					// unexpected => stop application pretty printing
					statistic.setLength(0);
				}
			}
			if (statistic.length() > 0) {
				return statistic.toString();
			} else {
				// CBOR plain pretty printing
				return element.toString();
			}
		} catch (CBORException e) {
			// plain payload
			e.printStackTrace();
			return StringUtil.byteArray2Hex(payload);
		}
	}

	/**
	 * Get UUID as device ID.
	 * 
	 * Read UUID from {@link #UUID_FILE} properties file with key
	 * {@link #UUID_KEY}, if file is available. If the file has no
	 * {@link #UUID_KEY}, use "anonymous" as UUID. If the properties file is not
	 * available, create a new random UUID and store it in that file.
	 * 
	 * @return UUID
	 */
	public static String getUUID(boolean reset) {
		Properties props = new Properties();
		if (!reset) {
			try (FileReader reader = new FileReader(UUID_FILE)) {
				props.load(reader);
				String uid = props.getProperty(UUID_KEY);
				if (uid == null) {
					uid = "anonymous";
				}
				return uid;
			} catch (FileNotFoundException e) {
			} catch (IOException e) {
			}
		}
		try (FileWriter writer = new FileWriter(UUID_FILE)) {
			String uid = UUID.randomUUID().toString();
			props.setProperty(UUID_KEY, uid);
			props.store(writer, "Californium CoAP UUID file");
			return uid;
		} catch (IOException e) {
		}
		return "anonymous";
	}
}
