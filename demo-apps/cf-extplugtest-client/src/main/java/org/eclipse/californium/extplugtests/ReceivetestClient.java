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
 *    Bosch Software Innovations GmbH - initial implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use special properties file
 *                                                    for configuration
 ******************************************************************************/

package org.eclipse.californium.extplugtests;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;
import java.util.UUID;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.plugtests.ClientInitializer;
import org.eclipse.californium.plugtests.ClientInitializer.Arguments;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

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
	public static void main(String[] args) {

		if (args.length == 0) {

			System.out.println("\nCalifornium (Cf) Receivetest Client");
			System.out.println("(c) 2017, Bosch Software Innovations GmbH and others");
			System.out.println();
			System.out.println("Usage: " + ReceivetestClient.class.getSimpleName() + " [-v] [-j] [-r|-x|-i id pw] URI");
			System.out.println("  -v        : verbose. Enable message tracing.");
			System.out.println("  -j        : use JSON format.");
			System.out.println("  -r        : use raw public certificate. Default PSK.");
			System.out.println("  -x        : use x.509 certificate");
			System.out.println("  -i id pw  : use PSK with id and password");
			System.out.println("  URI       : The CoAP URI of the extended Plugtest server to test (coap://<host>[:<port>])");
			System.out.println();
			System.out.println("Example: " + ReceivetestClient.class.getSimpleName() + " coap://californium.eclipse.org:5783");
			System.exit(-1);
		}

		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		Arguments arguments = ClientInitializer.init(config, args);

		String uuid = getUUID();
		CoapClient client = new CoapClient(arguments.uri);
		Request request = Request.newPost();
		if (arguments.json) {
			request.getOptions().setAccept(APPLICATION_JSON);
		}
		request.setURI(
				arguments.uri + "/requests?dev=" + uuid + "&rid=" + REQUEST_ID_PREFIX + System.currentTimeMillis());
		CoapResponse coapResponse = client.advanced(request);

		if (coapResponse != null) {
			if (CONTENT == coapResponse.getCode() && coapResponse.getOptions().getContentFormat() == APPLICATION_JSON) {
				// JSON success
				System.out.println();
				Response response = coapResponse.advanced();
				String payload = response.getPayloadString();
				System.out.println("Payload: " + payload.length() + " bytes");
				Long rtt = response.getRTT();
				if (rtt != null) {
					System.out.println("RTT: " + rtt + "ms");
				}
				System.out.println();
				String statistic = processJSON(response.getPayloadString(), "", arguments.verbose);
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

		System.exit(0);
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
								statistic.append("Request: ").append(format.format(new Date(requestTime)));
								long diff = time - requestTime;
								if (-MAX_DIFF_TIME_IN_MILLIS < diff && diff < MAX_DIFF_TIME_IN_MILLIS) {
									statistic.append(", received: ").append(diff).append(" ms");
								} else {
									statistic.append(", received: ").append(format.format(new Date(time)));
								}
								if (hit) {
									statistic.append(" * lost response!");
								}
								statistic.append(System.lineSeparator());
							} else {
								statistic.append("Request: ").append(rid);
								statistic.append(", received: ").append(format.format(new Date(time)));
								statistic.append(System.lineSeparator());
							}
						} else {
							long time = object.get("systemstart").getAsLong();
							statistic.append("Server's system start: ").append(format.format(new Date(time)));
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
	public static String getUUID() {
		Properties props = new Properties();
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
