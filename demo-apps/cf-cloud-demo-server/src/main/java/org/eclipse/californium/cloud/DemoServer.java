/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud;

import java.io.File;

import org.eclipse.californium.cloud.BaseServer.ServerConfig;
import org.eclipse.californium.cloud.option.TimeOption;
import org.eclipse.californium.core.coap.option.MapBasedOptionRegistry;
import org.eclipse.californium.core.coap.option.OptionRegistry;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.elements.config.Configuration;

import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;

/**
 * The cloud demo server.
 * <p>
 * Read {@link Configuration} and start the {@link BaseServer}.
 * 
 * @since 3.12
 */
public class DemoServer {

	private static final File CONFIG_FILE = new File("CaliforniumCloudDemo3.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Cloud-Demo Server";

	@Command(name = "CloudDemoServer", version = "(c) 2024, Contributors to the Eclipse Foundation.", footer = { "",
			"Examples:", "  DemoServer --no-loopback --device-file devices.txt",
			"    (DemoServer listening only on external network interfaces.)", "",
			"  DemoServer --store-file dtls.bin --store-max-age 168 \\",
			"                --store-password64 ZVhiRW5pdkx1RUs2dmVoZg== \\",
			"                --device-file devices.txt", "",
			"    (DemoServer with device credentials from file and dtls-graceful restart.",
			"     Devices/sessions with no exchange for more then a week (168 hours) are", "     skipped when saving.)",
			"", "  DemoServer --store-file dtls.bin --store-max-age 168 \\",
			"                --store-password64 ZVhiRW5pdkx1RUs2dmVoZg== \\",
			"                --device-file devices.txt --https-credenitals .", "",
			"    (DemoServer with device credentials from file and dtls-graceful restart.",
			"     A simple HTTP server is started at port 8080 using the x509 certificates",
			"     from the current directory (certificate is required to be provided).",
			"     Devices/sessions with no exchange for more then a week (168 hours) are", "     skipped when saving.)",
			"", })
	public static class Config extends ServerConfig {

		@ArgGroup(exclusive = false)
		public HttpsConfig https;

		@Override
		public void defaults() {
			super.defaults();
			if (https != null) {
				super.https = https;
			}
		}

	}

	public static void main(String[] args) {
		OptionRegistry registry = MapBasedOptionRegistry.builder()
				.add(StandardOptionRegistry.getDefaultOptionRegistry())
				.add(TimeOption.DEFINITION, TimeOption.DEPRECATED_DEFINITION)
				.build();

		StandardOptionRegistry.setDefaultOptionRegistry(registry);
		Configuration configuration = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, BaseServer.DEFAULTS);
		BaseServer.start(args, DemoServer.class.getSimpleName(), new Config(), new BaseServer(configuration));
	}
}
