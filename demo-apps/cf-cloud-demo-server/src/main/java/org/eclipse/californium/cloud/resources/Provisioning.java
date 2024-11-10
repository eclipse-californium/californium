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
package org.eclipse.californium.cloud.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.BAD_REQUEST;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CHANGED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONFLICT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.FORBIDDEN;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.INTERNAL_SERVER_ERROR;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.UNAUTHORIZED;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.io.StringWriter;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.californium.cloud.option.TimeOption;
import org.eclipse.californium.cloud.util.DeviceParser;
import org.eclipse.californium.cloud.util.DeviceProvisioningConsumer;
import org.eclipse.californium.cloud.util.PrincipalInfo;
import org.eclipse.californium.cloud.util.PrincipalInfo.Type;
import org.eclipse.californium.cloud.util.PrincipalInfoProvider;
import org.eclipse.californium.cloud.util.ResultConsumer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.util.PemUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Devices provisioning resource.
 * 
 * @since 3.13
 */
public class Provisioning extends ProtectedCoapResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(Provisioning.class);

	private static final SimpleDateFormat ISO_DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");

	public static final String RESOURCE_NAME = "prov";

	private final int[] CONTENT_TYPES = { TEXT_PLAIN };

	/**
	 * Device provisioning consumer.
	 */
	private final DeviceProvisioningConsumer devices;

	/**
	 * Create device provisioning resource.
	 * 
	 * @param devices device provisioning consumer
	 */
	public Provisioning(DeviceProvisioningConsumer devices) {
		super(RESOURCE_NAME, Type.CA, Type.PROVISIONING);
		Arrays.sort(CONTENT_TYPES);
		getAttributes().setTitle("Device provisioning resource.");
		getAttributes().addContentTypes(CONTENT_TYPES);
		this.devices = devices;
	}

	@Override
	public void handlePOST(final CoapExchange exchange) {

		int format = exchange.getRequestOptions().getContentFormat();
		if (format != UNDEFINED && Arrays.binarySearch(CONTENT_TYPES, format) < 0) {
			exchange.respond(NOT_ACCEPTABLE);
			return;
		}

		Principal principal = getPrincipal(exchange);
		PrincipalInfo info = getPrincipalInfo(exchange);
		if (info.type == Type.DEVICE) {
			// provision already available device
			info = getDeviceInfoCa(principal);
			if (info == null) {
				LOGGER.info("CA not available.");
				exchange.respond(FORBIDDEN, "CA not available.");
				return;
			}
		}
		if (allowed(info.type)) {
			String payload = exchange.getRequestText();
			if (payload.isEmpty()) {
				exchange.respond(BAD_REQUEST, "Missing provisioning payload.");
			} else {
				try {
					final TimeOption timeOption = TimeOption.getMessageTime(exchange.advanced().getRequest());
					final long time = timeOption.getLongValue();
					payload = "# added " + format(time) + " by " + info.name + StringUtil.lineSeparator() + payload;
					if (info.type == Type.CA) {
						X509CertPath certPath = (X509CertPath) principal;
						try {
							StringWriter writer = new StringWriter();
							byte[] data = certPath.getTarget().getEncoded();
							writer.write(StringUtil.lineSeparator());
							writer.write(DeviceParser.X509_POSTFIX);
							writer.write('=');
							writer.write(StringUtil.lineSeparator());
							PemUtil.write("CERTIFICATE", data, writer);
							payload = payload + writer.toString();
						} catch (CertificateEncodingException e) {
						}
					}
					LOGGER.debug("{}", payload);
					devices.add(info, time, payload, new ResultConsumer() {

						private final AtomicBoolean done = new AtomicBoolean();

						@Override
						public void results(ResultCode code, String message) {
							if (done.compareAndSet(false, true)) {
								ResponseCode responseCode = INTERNAL_SERVER_ERROR;
								switch (code) {
								case SUCCESS:
									responseCode = CHANGED;
									break;
								case PROVISIONING_ERROR:
									responseCode = CONFLICT;
									break;
								case SERVER_ERROR:
								default:
									break;
								}
								Response response = new Response(responseCode);
								response.setPayload(message);
								response.getOptions().setContentFormat(TEXT_PLAIN);
								// respond with time?
								final TimeOption responseTimeOption = timeOption.adjust();
								if (responseTimeOption != null) {
									response.getOptions().addOtherOption(responseTimeOption);
								}
								exchange.respond(response);
								LOGGER.info("{}", response);
							}
						}
					});
				} catch (Throwable t) {
					exchange.respond(INTERNAL_SERVER_ERROR, "Provisioning failed, " + t.getMessage());
				}
			}
		} else {
			LOGGER.info("No permission to added device credentials.");
			exchange.respond(FORBIDDEN, "No provisioning permission.");
		}
	}

	public static PrincipalInfo getDeviceInfoCa(Principal principal) {
		if (!(principal instanceof X509CertPath)) {
			LOGGER.warn("Principal is not X.509 based! {}", principal.getClass().getSimpleName());
			return null;
		}
		X509CertPath x509 = (X509CertPath) principal;
		PrincipalInfoProvider provider = x509.getExtendedInfo().get(PrincipalInfo.INFO_PROVIDER,
				PrincipalInfoProvider.class);
		if (provider == null) {
			LOGGER.warn("Principal has no device-info-provider assigned!");
			return null;
		}
		X509Certificate anchor = x509.getAnchor();
		if (anchor == null) {
			LOGGER.warn("Principal has no CA.");
			return null;
		}
		return provider.getPrincipalInfo(X509CertPath.fromCertificatesChain(anchor));
	}

	@Override
	protected ResponseCode checkPermission(final Exchange exchange) {
		final PrincipalInfo info = getPrincipalInfo(exchange);
		if (info == null) {
			return UNAUTHORIZED;
		}
		if (info.type == Type.DEVICE) {
			if (!(getPrincipal(exchange) instanceof X509CertPath)) {
				return FORBIDDEN;
			}
		} else if (!allowed(info.type)) {
			return FORBIDDEN;
		}
		return checkOperationPermission(info, exchange, exchange.getRequest().getCode().write);
	}

	public static String format(long millis) {
		return ISO_DATE_FORMAT.format(new Date(millis));
	}
}
