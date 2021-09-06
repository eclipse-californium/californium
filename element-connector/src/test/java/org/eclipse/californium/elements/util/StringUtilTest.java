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
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assume.assumeFalse;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Set;

import org.junit.Test;

public class StringUtilTest {

	@Test
	public void testHex2ByteArray() {
		String line = "4130010A";
		byte[] result = StringUtil.hex2ByteArray(line);

		assertThat(result, is(new byte[] { 0x41, 0x30, 0x01, 0x0a }));
	}

	@Test
	public void testHex2CharArray() {
		String line = "4130010A";
		char[] result = StringUtil.hex2CharArray(line);

		assertThat(result, is(new char[] { 'A', '0', 0x01, '\n' }));
	}

	@Test
	public void testHex2CharArrayWithNull() {
		String line = null;
		char[] result = StringUtil.hex2CharArray(line);

		assertThat(result, is((char[]) null));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testHex2CharArrayIllegalArgumentLength() {
		String line = "4130010A0";
		StringUtil.hex2CharArray(line);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testHex2CharArrayIllegalArgumentContent() {
		String line = "4130010A0Z";
		StringUtil.hex2CharArray(line);
	}

	@Test
	public void testGetUriHostname() throws URISyntaxException, UnknownHostException {
		String hostname = StringUtil.getUriHostname(InetAddress.getLoopbackAddress());
		assertThat(hostname, is("127.0.0.1"));

		URI test = new URI("coap", null, hostname, 5683, null, null, null);
		assertThat(test.toASCIIString(), is("coap://127.0.0.1:5683"));

		hostname = StringUtil.getUriHostname(Inet6Address.getByName("[FF02::FD]"));
		assertThat(hostname, is("ff02:0:0:0:0:0:0:fd"));

		test = new URI("coap", null, hostname, 5683, null, null, null);
		assertThat(test.toASCIIString(), is("coap://[ff02:0:0:0:0:0:0:fd]:5683"));
	}

	@Test
	public void testGetUriHostnameWithScope() throws URISyntaxException, UnknownHostException {
		Set<String> scopes = NetworkInterfacesUtil.getIpv6Scopes();
		assumeFalse("scope networkinterfaces required!", scopes.isEmpty());

		String scope = scopes.iterator().next();

		String hostname = StringUtil.getUriHostname(Inet6Address.getByName("[FF02::FD%" + scope + "]"));
		assertThat(hostname, is("ff02:0:0:0:0:0:0:fd%25" + scope));

		URI test = new URI("coap", null, hostname, 5683, null, null, null);
		assertThat(test.toASCIIString(), is("coap://[ff02:0:0:0:0:0:0:fd%25" + scope + "]:5683"));
	}

	@Test
	public void testToHostString() throws URISyntaxException, UnknownHostException {
		InetSocketAddress address = new InetSocketAddress("localhost", 5683);
		assertThat(StringUtil.toHostString(address), is("localhost"));
		address = new InetSocketAddress("127.0.0.1", 5683);
		assertThat(StringUtil.toHostString(address), is("127.0.0.1"));
		address = InetSocketAddress.createUnresolved("my.test.server", 5683);
		assertThat(StringUtil.toHostString(address), is("my.test.server"));
		InetAddress dest = InetAddress.getByAddress(new byte[] { 8, 8, 8, 8 });
		address = new InetSocketAddress(dest, 5683);
		assertThat(StringUtil.toHostString(address), is("8.8.8.8"));
	}

}
