/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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

package org.eclipse.californium.examples.util;

import static org.eclipse.californium.elements.util.StandardCharsets.ISO_8859_1;

import java.util.List;

import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Printer for coap-response.
 * 
 * @since 3.0
 */
public class CoapResponsePrinter {

	/**
	 * Print provided coap-response.
	 * 
	 * @param response coap-response, or {@code null}, if not received.
	 */
	public static void printResponse(CoapResponse response) {
		if (response != null) {
			List<byte[]> etags = response.getOptions().getETags();
			for (byte[] etag : etags) {
				try {
					for (byte e : etag) {
						if (' ' > e) {
							throw new Error("no ascii!");
						}
					}
					String text = new String(etag, ISO_8859_1);
					System.out.println("etag: '" + text + "', 0x" + StringUtil.byteArray2Hex(etag));
				} catch (Error e) {
					System.out.println("etag: 0x" + StringUtil.byteArray2Hex(etag));
				}
			}
			int format = response.getOptions().getContentFormat();
			if (format != MediaTypeRegistry.TEXT_PLAIN && format != MediaTypeRegistry.UNDEFINED) {
				System.out.print(MediaTypeRegistry.toString(format) + " - ");
			}
			String text = response.getResponseText();
			if (text.isEmpty()) {
				System.out.println(response.getCode() + "/" + response.getCode().name());
			} else {
				System.out.println(
						response.getCode() + "/" + response.getCode().name() + " --- " + response.getResponseText());
			}
		} else {
			System.out.println("timeout!");
		}
	}
}
