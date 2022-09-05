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
package org.eclipse.californium.proxy2.http;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;

import java.util.Arrays;
import java.util.List;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.ExpectedExceptionWrapper;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.proxy2.InvalidMethodException;
import org.eclipse.californium.proxy2.TranslationException;
import org.hamcrest.Description;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;

@Category(Small.class)
public class CrossProtocolTranslatorTest {

	/**
	 * No exception expected by default
	 */
	@Rule
	public ExpectedException exception = ExpectedExceptionWrapper.none();

	private MappingProperties defaultMappings = new MappingProperties();
	private CrossProtocolTranslator translator = new CrossProtocolTranslator(defaultMappings);
	private CrossProtocolTranslator.EtagTranslator httpEtagTranslator = new CrossProtocolTranslator.HttpServerEtagTranslator();
	private CrossProtocolTranslator.EtagTranslator coapEtagTranslator = new CrossProtocolTranslator.CoapServerEtagTranslator();

	@Test
	public void testCoapResponseCode() throws Exception {
		assertThat(translator.getCoapResponseCode(Code.GET, 200), is(ResponseCode.CONTENT));
		assertThat(translator.getCoapResponseCode(Code.PUT, 201), is(ResponseCode.CREATED));
		assertThat(translator.getCoapResponseCode(Code.POST, 204), is(ResponseCode.CHANGED));
		assertThat(translator.getCoapResponseCode(Code.PUT, 204), is(ResponseCode.CHANGED));
		assertThat(translator.getCoapResponseCode(Code.DELETE, 204), is(ResponseCode.DELETED));

		assertThat(translator.getCoapResponseCode(Code.GET, 401), is(ResponseCode.UNAUTHORIZED));
		assertThat(translator.getCoapResponseCode(Code.GET, 502), is(ResponseCode.BAD_GATEWAY));
	}

	@Test
	public void testInvalidCoapResponseCode() throws Exception {
		exception.expect(TranslationException.class);
		exception.expectMessage(containsString("missing"));
		translator.getCoapResponseCode(Code.GET, 10);
	}

	@Test
	public void testNullCoapCodeForCoapResponseCode() throws Exception {
		exception.expect(NullPointerException.class);
		translator.getCoapResponseCode(null, 10);
	}

	@Test
	public void testCoapCode() throws Exception {
		assertThat(translator.getCoapCode("GET"), is(Code.GET));
		assertThat(translator.getCoapCode("HEAD"), is(Code.GET));
		assertThat(translator.getCoapCode("PUT"), is(Code.PUT));
	}

	@Test
	public void testInvalidCoapCode() throws Exception {
		exception.expect(InvalidMethodException.class);
		exception.expectMessage(containsString("INTERNAL_SERVER_ERROR"));
		translator.getCoapCode("mystic");
	}

	@Test
	public void testNullCoapCode() throws Exception {
		exception.expect(NullPointerException.class);
		translator.getCoapCode(null);
	}

	@Test
	public void testSpecialCoapCode() throws Exception {
		exception.expect(InvalidMethodException.class);
		exception.expectMessage(containsString("NOT_IMPLEMENTED"));
		translator.getCoapCode("trace");
	}

	@Test
	public void testCoapMediaType() throws Exception {
		assertThat(translator.getCoapMediaType(ContentType.TEXT_PLAIN.getMimeType()), is(MediaTypeRegistry.TEXT_PLAIN));
		assertThat(translator.getCoapMediaType(ContentType.APPLICATION_JSON.getMimeType()),
				is(MediaTypeRegistry.APPLICATION_JSON));
		assertThat(translator.getCoapMediaType(ContentType.APPLICATION_XML.getMimeType()),
				is(MediaTypeRegistry.APPLICATION_XML));
		assertThat(translator.getCoapMediaType("text/xml"), is(MediaTypeRegistry.APPLICATION_XML));
		assertThat(translator.getCoapMediaType("text/html"), is(MediaTypeRegistry.TEXT_PLAIN));
		assertThat(translator.getCoapMediaType("text/xyz"), is(MediaTypeRegistry.TEXT_PLAIN));
		assertThat(translator.getCoapMediaType("text"), is(MediaTypeRegistry.TEXT_PLAIN));
	}

	@Test
	public void testNullCoapMediaType() throws Exception {
		exception.expect(NullPointerException.class);
		translator.getCoapMediaType(null);
	}

	@Test
	public void testSpecialCoapMediaType() throws Exception {
		assertThat(translator.getCoapMediaType("application/x+y+z"), is(MediaTypeRegistry.APPLICATION_OCTET_STREAM));
		assertThat(translator.getCoapMediaType("application/x+y+z", MediaTypeRegistry.APPLICATION_XML),
				is(MediaTypeRegistry.APPLICATION_XML));
		assertThat(translator.getCoapMediaType("bin"), is(MediaTypeRegistry.APPLICATION_OCTET_STREAM));
	}

	@Test
	public void testCoapOptionsHttpEtag() throws Exception {
		Header[] headers = { new BasicHeader("etag", "test"), new BasicHeader("etag", "ab"),
				new BasicHeader("etag", "abc") };
		List<Option> coapOptions = translator.getCoapOptions(headers, httpEtagTranslator);
		assertThat(coapOptions.size(), is(3));
		OptionSet options = new OptionSet().addOptions(coapOptions);
		assertThat(options.getETagCount(), is(3));
		assertThat(options.getETags().get(0), is("test".getBytes()));
		assertThat(options.getETags().get(1), is("ab".getBytes()));
		assertThat(options.getETags().get(2), is("abc".getBytes()));
	}

	@Test
	public void testCoapOptionsCoapEtag() throws Exception {
		Header[] headers = { new BasicHeader("etag", "01abcd34"), new BasicHeader("etag", "7788"),
				new BasicHeader("etag", "abd") };
		List<Option> coapOptions = translator.getCoapOptions(headers, coapEtagTranslator);
		assertThat(coapOptions.size(), is(2));
		OptionSet options = new OptionSet().addOptions(coapOptions);
		assertThat(options.getETagCount(), is(2));
		assertThat(options.getETags().get(0), is(StringUtil.hex2ByteArray("01abcd34")));
		assertThat(options.getETags().get(1), is(StringUtil.hex2ByteArray("7788")));
	}

	@Test
	public void testCoapOptionsTooLargeEtag() throws Exception {
		Header[] headers = { new BasicHeader("etag", "test1234567890toomuch"), new BasicHeader("etag", "test") };
		List<Option> coapOptions = translator.getCoapOptions(headers, httpEtagTranslator);
		assertThat(coapOptions.size(), is(1));
		OptionSet options = new OptionSet().addOptions(coapOptions);
		assertThat(options.getETagCount(), is(1));
		assertThat(options.getETags().get(0), is("test".getBytes()));
	}

	@Test
	public void testCoapOptionsIfMatch() throws Exception {
		Header[] headers = { new BasicHeader("if-match", "test"), new BasicHeader("if-match", "ab") };
		List<Option> coapOptions = translator.getCoapOptions(headers, httpEtagTranslator);
		assertThat(coapOptions.size(), is(2));
		OptionSet options = new OptionSet().addOptions(coapOptions);
		assertThat(options.getIfMatchCount(), is(2));
		assertThat(options.getIfMatch().get(0), is("test".getBytes()));
		assertThat(options.getIfMatch().get(1), is("ab".getBytes()));
	}

	@Test
	public void testCoapOptionsIfNoneMatch() throws Exception {
		Header[] headers = { new BasicHeader("if-none-match", "*") };
		List<Option> coapOptions = translator.getCoapOptions(headers, httpEtagTranslator);
		assertThat(coapOptions.size(), is(1));
		OptionSet options = new OptionSet().addOptions(coapOptions);
		assertThat(options.hasIfNoneMatch(), is(true));
	}

	@Test
	public void testCoapOptionsInvalidIfNoneMatch() throws Exception {
		Header[] headers = { new BasicHeader("if-none-match", "1234") };
		List<Option> coapOptions = translator.getCoapOptions(headers, httpEtagTranslator);
		assertThat(coapOptions.size(), is(0));
	}

	@Test
	public void testCoapOptionsMaxAge() throws Exception {
		Header[] headers = { new BasicHeader("cache-control", "max-age=12") };
		List<Option> coapOptions = translator.getCoapOptions(headers, httpEtagTranslator);
		assertThat(coapOptions.size(), is(1));
		OptionSet options = new OptionSet().addOptions(coapOptions);
		assertThat(options.hasMaxAge(), is(true));
		assertThat(options.getMaxAge(), is(12L));
	}

	@Test
	public void testCoapOptionsLocation() throws Exception {
		Header[] headers = { new BasicHeader("Content-Location", "/to/twin") };
		List<Option> coapOptions = translator.getCoapOptions(headers, httpEtagTranslator);
		assertThat(coapOptions.size(), is(2));
		OptionSet options = new OptionSet().addOptions(coapOptions);
		assertThat(options.getLocationPathCount(), is(2));
		assertThat(options.getLocationPathString(), is("to/twin"));

		headers = new Header[] { new BasicHeader("Content-Location", "/to/twin?var=a") };
		coapOptions = translator.getCoapOptions(headers, httpEtagTranslator);
		assertThat(coapOptions.size(), is(3));
		options = new OptionSet().addOptions(coapOptions);
		assertThat(options.getLocationPathCount(), is(2));
		assertThat(options.getLocationPathString(), is("to/twin"));
		assertThat(options.getLocationQueryCount(), is(1));
		assertThat(options.getLocationQueryString(), is("var=a"));
	}

	@Test
	public void testCoapOptionsAccept() throws Exception {
		Header[] headers = { new BasicHeader("Accept", "text/plain; charset=UTF-8") };
		List<Option> coapOptions = translator.getCoapOptions(headers, httpEtagTranslator);
		assertThat(coapOptions.size(), is(1));
		OptionSet options = new OptionSet().addOptions(coapOptions);
		assertThat(options.getAccept(), is(MediaTypeRegistry.TEXT_PLAIN));
	}

	@Test
	public void testCoapOptionsAcceptWithqualifier() throws Exception {
		Header[] headers = { new BasicHeader("Accept", "plain/text, text/plain; q=0.6, application/json") };
		List<Option> coapOptions = translator.getCoapOptions(headers, httpEtagTranslator);
		assertThat(coapOptions.size(), is(1));
		OptionSet options = new OptionSet().addOptions(coapOptions);
		assertThat(options.getAccept(), is(MediaTypeRegistry.APPLICATION_JSON));
	}

	@Test
	public void testCoapOptionsContentFormatIgnored() throws Exception {
		Header[] headers = { new BasicHeader("Content-Type", "text/plain; charset=UTF-8") };
		List<Option> coapOptions = translator.getCoapOptions(headers, httpEtagTranslator);
		assertThat(coapOptions.size(), is(0));
	}

	@Test
	public void testNullCoapOptions() throws Exception {
		exception.expect(NullPointerException.class);
		translator.getCoapOptions(null, httpEtagTranslator);
	}

	@Test
	public void testHttpCode() throws Exception {
		assertThat(translator.getHttpCode(ResponseCode.CONTENT), is(200));
		assertThat(translator.getHttpCode(ResponseCode.CHANGED), is(204));
		assertThat(translator.getHttpCode(ResponseCode.BAD_OPTION), is(400));
		assertThat(translator.getHttpCode(ResponseCode.BAD_GATEWAY), is(502));
	}

	@Test
	public void testInvalidHttpCode() throws Exception {
		exception.expect(TranslationException.class);
		translator.getHttpCode(ResponseCode.REQUEST_ENTITY_INCOMPLETE);
	}

	@Test
	public void testNullHttpCode() throws Exception {
		exception.expect(NullPointerException.class);
		translator.getHttpCode(null);
	}

	@Test
	public void testHttpMethod() throws Exception {
		assertThat(translator.getHttpMethod(Code.GET), is("GET"));
		assertThat(translator.getHttpMethod(Code.POST), is("POST"));
	}

	@Test
	public void testInvalidHttpMethod() throws Exception {
		exception.expect(TranslationException.class);
		translator.getHttpMethod(Code.CUSTOM_30);
	}

	@Test
	public void testNullHttpMethod() throws Exception {
		exception.expect(NullPointerException.class);
		translator.getHttpMethod(null);
	}

	@Test
	public void testHttpContentType() throws Exception {
		assertThat(translator.getHttpContentType(MediaTypeRegistry.TEXT_PLAIN).toString(),
				is("text/plain; charset=UTF-8"));
		assertThat(translator.getHttpContentType(MediaTypeRegistry.APPLICATION_JSON).toString(),
				is("application/json; charset=UTF-8"));
		assertThat(translator.getHttpContentType(MediaTypeRegistry.APPLICATION_XML).toString(), is("application/xml"));
	}

	@Test
	public void testInvalidHttpContentType() throws Exception {
		exception.expect(TranslationException.class);
		translator.getHttpContentType(-1);
	}

	@Test
	public void testHttpHeader() throws Exception {
		OptionSet set = new OptionSet();
		set.setUriHost("test");
		set.setLocationPath("test/location");
		set.setLocationQuery("t1=a&var");
		set.setAccept(MediaTypeRegistry.APPLICATION_JSON);
		set.addETag(new byte[] { 0x01, 0x02 });
		set.setMaxAge(24);
		set.setContentFormat(MediaTypeRegistry.APPLICATION_XML);
		List<Header> httpHeaders = Arrays.asList(translator.getHttpHeaders(set.asSortedList(), coapEtagTranslator));
		assertThat(httpHeaders.size(), is(4));
		assertThat(httpHeaders, hasItem(hasHttpHeader("Etag", "0102")));
		assertThat(httpHeaders, hasItem(hasHttpHeader("Accept", "application/json; charset=UTF-8")));
		assertThat(httpHeaders, hasItem(hasHttpHeader("Cache-Control", "max-age=24")));
		assertThat(httpHeaders, hasItem(hasHttpHeader("Content-Location", "/test/location?t1=a&var")));
	}

	/**
	 * Check, if http header matches.
	 * 
	 * @param <T>
	 * @param header
	 * @return matcher
	 */
	private static org.hamcrest.Matcher<Header> hasHttpHeader(String name, String value) {
		return new HasHttpHeader(name, value);
	}

	/**
	 * Has http header.
	 */
	private static class HasHttpHeader extends org.hamcrest.BaseMatcher<Header> {

		private final String name;
		private final String value;

		private HasHttpHeader(String name, String value) {
			this.name = name;
			this.value = value;
		}

		@Override
		public boolean matches(Object item) {
			if (!(item instanceof Header)) {
				throw new IllegalArgumentException(
						"value type " + item.getClass().getSimpleName() + " doesn't match Header!");
			}
			Header header = (Header) item;
			return name.equalsIgnoreCase(header.getName()) && value.equals(header.getValue());
		}

		@Override
		public void describeTo(Description description) {
			description.appendText("Header{");
			description.appendText(name);
			description.appendText(": ");
			description.appendText(value);
			description.appendText("}");
		}
	}

}
