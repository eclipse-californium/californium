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

import org.eclipse.californium.elements.category.Small;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class StringUtilTest {

	@Test
	public void testHex2ByteArray() {
		String line = "4130010A";
		byte[] result = StringUtil.hex2ByteArray(line);

		assertThat(result, is(new byte[] { 0x41, 0x30, 0x01, 0x0a }));
	}

	@Test
	public void testByteArray2Hex() {
		byte[] data = { 0x41, 0x30, 0x01, 0x0a };
		String result = StringUtil.byteArray2Hex(data);
		assertThat(result, is("4130010A"));
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
	public void testBase64String2ByteArray() {
		String line = "QTABCg=="; // hex 4130010A
		byte[] result = StringUtil.base64ToByteArray(line);
		assertThat(result, is(new byte[] { 0x41, 0x30, 0x01, 0x0a }));
	}

	@Test
	public void testByteArray2Base64() {
		byte[] data = { 0x41, 0x30, 0x01, 0x0a };
		String result = StringUtil.byteArrayToBase64(data);
		assertThat(result, is("QTABCg=="));
	}

	@Test
	public void testBase64String2ByteArrayPadding() {
		String line = "QTABCg"; // hex 4130010A
		byte[] result = StringUtil.base64ToByteArray(line);
		assertThat(result, is(new byte[] { 0x41, 0x30, 0x01, 0x0a }));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testBase64String2ByteArrayIllegalLength() {
		String line = "QTABC";
		StringUtil.base64ToByteArray(line);
	}

	@Test
	public void testBase64String2ByteArrayIllegalCharacter() {
		String line = "QTABC\u0100";
		byte[] result = StringUtil.base64ToByteArray(line);
		// will change with next major release to IllegalArgumentException
		assertThat(result, is(Bytes.EMPTY));
	}

	@Test
	public void testBase64CharArray2ByteArray() {
		char[] line = "QTABCg==".toCharArray(); // hex 4130010A
		byte[] result = StringUtil.base64ToByteArray(line);
		assertThat(result, is(new byte[] { 0x41, 0x30, 0x01, 0x0a }));
	}

	@Test
	public void testByteArray2Base64CharArray() {
		byte[] data = { 0x41, 0x30, 0x01, 0x0a };
		char[] result = StringUtil.byteArrayToBase64CharArray(data);
		assertThat(result, is("QTABCg==".toCharArray()));
	}

	@Test
	public void testBase64CharArray2ByteArrayPadding() {
		char[] line = "QTABCg".toCharArray(); // hex 4130010A
		byte[] result = StringUtil.base64ToByteArray(line);
		assertThat(result, is(new byte[] { 0x41, 0x30, 0x01, 0x0a }));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testBase64CharArray2ByteArrayIllegalLength() {
		char[] line = "QTABC".toCharArray();
		StringUtil.base64ToByteArray(line);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testBase64CharArray2ByteArrayIllegalCharacter() {
		char[] line = "QTABC\u0100".toCharArray();
		StringUtil.base64ToByteArray(line);
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

		// work-around for openjdk bug JDK-8199396.
		// some characters are not supported for the ipv6 scope.
		scope = scope.replaceAll("[-._~]", "");
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

	@Test
	public void testTrunc() {
		String text = "message";
		String result1 = StringUtil.trunc(text, 100);
		String result2 = StringUtil.trunc(text, 4);
		String result3 = StringUtil.trunc(text, 0);
		assertThat(result1, is(text));
		assertThat(result2, is("mess"));
		assertThat(result3, is(text));
	}

	@Test
	public void testTruncateTail() {
		String text = "message";
		assertThat(StringUtil.truncateTail(text, "agX"), is(text));
		assertThat(StringUtil.truncateTail(text, "age"), is("mess"));
		assertThat(StringUtil.truncateTail(text, ""), is(text));
		assertThat(StringUtil.truncateTail(text, "mes"), is(text));
	}

	@Test
	public void testTruncateStringBuilderTail() {
		StringBuilder text1 = new StringBuilder("message");
		StringBuilder text2 = new StringBuilder("message");
		StringBuilder text3 = new StringBuilder("message");
		StringBuilder text4 = new StringBuilder("message");
		assertThat(StringUtil.truncateTail(text1, "agX"), is(false));
		assertThat(StringUtil.truncateTail(text2, "age"), is(true));
		assertThat(StringUtil.truncateTail(text3, ""), is(false));
		assertThat(StringUtil.truncateTail(text4, "mes"), is(false));
		assertThat(text1.toString(), is("message"));
		assertThat(text2.toString(), is("mess"));
		assertThat(text3.toString(), is("message"));
		assertThat(text4.toString(), is("message"));
	}

	@Test
	public void testTruncateHeader() {
		String text = "message";
		assertThat(StringUtil.truncateHeader(text, "meX"), is(text));
		assertThat(StringUtil.truncateHeader(text, "mes"), is("sage"));
		assertThat(StringUtil.truncateHeader(text, ""), is(text));
		assertThat(StringUtil.truncateHeader(text, "age"), is(text));
	}

	@Test
	public void testTruncateStringBuilderHeader() {
		StringBuilder text1 = new StringBuilder("message");
		StringBuilder text2 = new StringBuilder("message");
		StringBuilder text3 = new StringBuilder("message");
		StringBuilder text4 = new StringBuilder("message");
		assertThat(StringUtil.truncateHeader(text1, "meX"), is(false));
		assertThat(StringUtil.truncateHeader(text2, "mes"), is(true));
		assertThat(StringUtil.truncateHeader(text3, ""), is(false));
		assertThat(StringUtil.truncateHeader(text4, "age"), is(false));
		assertThat(text1.toString(), is("message"));
		assertThat(text2.toString(), is("sage"));
		assertThat(text3.toString(), is("message"));
		assertThat(text4.toString(), is("message"));
	}

}
