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
package org.eclipse.californium.proxy2;

import static org.eclipse.californium.elements.util.StandardCharsets.ISO_8859_1;
import static org.eclipse.californium.elements.util.StandardCharsets.UTF_8;
import static org.eclipse.californium.proxy2.MappingProperties.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.UnmappableCharacterException;
import java.nio.charset.UnsupportedCharsetException;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpMessage;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.entity.AbstractHttpEntity;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.OptionNumberRegistry.optionFormats;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class providing the translations (mappings) from the HTTP message artefacts
 * to the CoAP message artefacts and vice versa.
 */
public class HttpTranslator {

	/**
	 * Property file containing the mappings between coap messages and http
	 * messages.
	 */
	private static final MappingProperties DEFAULT_HTTP_TRANSLATION_PROPERTIES = new MappingProperties(
			"Proxy2.properties");
	private MappingProperties translationMapping;

	// Error constants
	public static final int STATUS_TIMEOUT = HttpStatus.SC_GATEWAY_TIMEOUT;
	public static final int STATUS_NOT_FOUND = HttpStatus.SC_BAD_GATEWAY;
	public static final int STATUS_TRANSLATION_ERROR = HttpStatus.SC_BAD_GATEWAY;
	public static final int STATUS_URI_MALFORMED = HttpStatus.SC_BAD_REQUEST;
	public static final int STATUS_WRONG_METHOD = HttpStatus.SC_NOT_IMPLEMENTED;
	public static final int STATUS_INTERNAL_SERVER_ERROR = HttpStatus.SC_INTERNAL_SERVER_ERROR;

	private static final Logger LOGGER = LoggerFactory.getLogger(HttpTranslator.class);

	public HttpTranslator(String mappingPropertiesFileName) {
		translationMapping = new MappingProperties(mappingPropertiesFileName);
	}

	public HttpTranslator() {
		translationMapping = DEFAULT_HTTP_TRANSLATION_PROPERTIES;
	}

	public ResponseCode getCoapResponseCode(int code) throws TranslationException {
		ResponseCode responseCode = translationMapping.getCoapResponseCode(code);

		if (responseCode == null) {
			LOGGER.warn("coap response code missing for {}", code);
			throw new TranslationException("coap response-code missing!");
		}
		return responseCode;
	}

	public Code getCoapCode(String httpMethod) throws InvalidMethodException {
		return translationMapping.getCoapCode(httpMethod);
	}

	/**
	 * Gets the coap media type associated to the http entity. Firstly, it looks
	 * for a valid mapping in the property file. If this step fails, then it
	 * tries to explicitly map/parse the declared mime/type by the http entity.
	 * If even this step fails, it sets application/octet-stream as
	 * content-type.
	 * 
	 * @param httpMessage
	 * 
	 * 
	 * @return the coap media code associated to the http message entity. * @see
	 *         HttpHeader, ContentType, MediaTypeRegistry
	 */
	public int getCoapMediaType(HttpMessage httpMessage) {
		if (httpMessage == null) {
			throw new IllegalArgumentException("httpMessage == null");
		}

		// get the entity
		HttpEntity httpEntity = null;
		if (httpMessage instanceof HttpResponse) {
			httpEntity = ((HttpResponse) httpMessage).getEntity();
		} else if (httpMessage instanceof HttpEntityEnclosingRequest) {
			httpEntity = ((HttpEntityEnclosingRequest) httpMessage).getEntity();
		}

		// check that the entity is actually present in the http message
		if (httpEntity == null) {
			throw new IllegalArgumentException("The http message does not contain any httpEntity.");
		}

		// set the content-type with a default value
		int coapContentType = MediaTypeRegistry.UNDEFINED;

		// get the content-type from the entity
		ContentType contentType = ContentType.get(httpEntity);
		if (contentType == null) {
			// if the content-type is not set, search in the headers
			Header contentTypeHeader = httpMessage.getFirstHeader("content-type");
			if (contentTypeHeader != null) {
				String contentTypeString = contentTypeHeader.getValue();
				contentType = ContentType.parse(contentTypeString);
			}
		}

		// check if there is an associated content-type with the current http
		// message
		if (contentType != null) {
			// get the value of the content-type
			String httpContentTypeString = contentType.getMimeType();
			// delete the last part (if any)
			httpContentTypeString = httpContentTypeString.split(";")[0];

			// retrieve the mapping from the property file
			String coapContentTypeString = translationMapping
					.getProperty(KEY_HTTP_CONTENT_TYPE + httpContentTypeString);

			if (coapContentTypeString != null) {
				coapContentType = Integer.parseInt(coapContentTypeString);
			} else {
				// try to parse the media type if the property file has given to
				// mapping
				coapContentType = MediaTypeRegistry.parse(httpContentTypeString);
			}
		}

		// if not recognized, the content-type should be
		// application/octet-stream (draft-castellani-core-http-mapping 6.2)
		if (coapContentType == MediaTypeRegistry.UNDEFINED) {
			coapContentType = MediaTypeRegistry.APPLICATION_OCTET_STREAM;
		}

		return coapContentType;
	}

	/**
	 * Gets the coap options starting from an array of http headers. The
	 * content-type is not handled by this method. The method iterates over an
	 * array of headers and for each of them tries to find a mapping in the
	 * properties file, if the mapping does not exists it skips the header
	 * ignoring it. The method handles separately certain headers which are
	 * translated to options (such as accept or cache-control) whose content
	 * should be semantically checked or requires ad-hoc translation. Otherwise,
	 * the headers content is translated with the appropriate format required by
	 * the mapped option.
	 * 
	 * @param headers
	 * 
	 */
	public List<Option> getCoapOptions(Header[] headers) {
		if (headers == null) {
			throw new IllegalArgumentException("httpMessage == null");
		}

		List<Option> optionList = new LinkedList<Option>();

		// iterate over the headers
		for (Header header : headers) {
			try {
				String headerName = header.getName().toLowerCase();

				// FIXME: CoAP does no longer support multiple accept-options.
				// If an HTTP request contains multiple accepts, this method
				// fails. Therefore, we currently skip accepts at the moment.
				if (headerName.startsWith("accept"))
					continue;

				// get the mapping from the property file
				String optionCodeString = translationMapping.getProperty(KEY_HTTP_HEADER + headerName);

				// ignore the header if not found in the properties file
				if (optionCodeString == null || optionCodeString.isEmpty()) {
					continue;
				}

				// get the option number
				int optionNumber = OptionNumberRegistry.RESERVED_0;
				try {
					optionNumber = Integer.parseInt(optionCodeString.trim());
				} catch (Exception e) {
					LOGGER.warn("Problems in the parsing", e);
					// ignore the option if not recognized
					continue;
				}

				// ignore the content-type because it will be handled within the
				// payload
				if (optionNumber == OptionNumberRegistry.CONTENT_FORMAT) {
					continue;
				}

				// get the value of the current header
				String headerValue = header.getValue().trim();

				// if the option is accept, it needs to translate the
				// values
				if (optionNumber == OptionNumberRegistry.ACCEPT) {
					// remove the part where the client express the weight of
					// each
					// choice
					headerValue = headerValue.trim().split(";")[0].trim();

					// iterate for each content-type indicated
					for (String headerFragment : headerValue.split(",")) {
						// translate the content-type
						Integer[] coapContentTypes = { MediaTypeRegistry.UNDEFINED };
						if (headerFragment.contains("*")) {
							coapContentTypes = MediaTypeRegistry.parseWildcard(headerFragment);
						} else {
							coapContentTypes[0] = MediaTypeRegistry.parse(headerFragment);
						}

						// if is present a conversion for the content-type, then
						// add
						// a new option
						for (int coapContentType : coapContentTypes) {
							if (coapContentType != MediaTypeRegistry.UNDEFINED) {
								// create the option
								Option option = new Option(optionNumber, coapContentType);
								optionList.add(option);
							}
						}
					}
				} else if (optionNumber == OptionNumberRegistry.MAX_AGE) {
					int maxAge = 0;
					if (!headerValue.contains("no-cache")) {
						headerValue = headerValue.split(",")[0];
						if (headerValue != null) {
							int index = headerValue.indexOf('=');
							try {
								maxAge = Integer.parseInt(headerValue.substring(index + 1).trim());
							} catch (NumberFormatException e) {
								LOGGER.warn("Cannot convert cache control in max-age option", e);
								continue;
							}
						}
					}
					// create the option
					Option option = new Option(optionNumber, maxAge);
					// option.setValue(headerValue.getBytes(Charset.forName("ISO-8859-1")));
					optionList.add(option);
				} else {
					// create the option
					Option option = new Option(optionNumber);
					switch (OptionNumberRegistry.getFormatByNr(optionNumber)) {
					case INTEGER:
						option.setIntegerValue(Integer.parseInt(headerValue));
						break;
					case OPAQUE:
						option.setValue(headerValue.getBytes(ISO_8859_1));
						break;
					case STRING:
					default:
						option.setStringValue(headerValue);
						break;
					}
					// option.setValue(headerValue.getBytes(Charset.forName("ISO-8859-1")));
					optionList.add(option);
				}
			} catch (RuntimeException e) {
				// Martin: I have added this try-catch block. The problem is
				// that HTTP support multiple Accepts while CoAP does not. A
				// headder line might look like this:
				// Accept:
				// text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
				// This cannot be parsed into a single CoAP Option and yields a
				// NumberFormatException
				LOGGER.warn("Could not parse header line {}", header);
			}
		} // while (headerIterator.hasNext())

		return optionList;
	}

	/**
	 * Method to map the http entity of a http message in a coherent payload for
	 * the coap message. The method simply gets the bytes from the entity and,
	 * if needed changes the charset of the obtained bytes to UTF-8.
	 * 
	 * @param httpEntity the http entity
	 * 
	 * @return byte[]
	 * @throws TranslationException the translation exception
	 */
	public byte[] getCoapPayload(HttpEntity httpEntity) throws TranslationException {
		if (httpEntity == null) {
			throw new IllegalArgumentException("httpEntity == null");
		}

		byte[] payload = null;
		try {
			// get the bytes from the entity
			payload = EntityUtils.toByteArray(httpEntity);
			if (payload != null && payload.length > 0) {

				// the only supported charset in CoAP is UTF-8
				Charset coapCharset = UTF_8;

				// get the charset for the http entity
				ContentType httpContentType = ContentType.getOrDefault(httpEntity);
				Charset httpCharset = httpContentType.getCharset();

				// check if the charset is the one allowed by coap
				if (httpCharset != null && !httpCharset.equals(coapCharset)) {
					// translate the payload to the utf-8 charset
					payload = changeCharset(payload, httpCharset, coapCharset);
				}
			}
		} catch (IOException e) {
			LOGGER.warn("Cannot get the content of the http entity: " + e.getMessage());
			throw new TranslationException("Cannot get the content of the http entity", e);
		} finally {
			try {
				// ensure all content has been consumed, so that the
				// underlying connection could be re-used
				EntityUtils.consume(httpEntity);
			} catch (IOException e) {

			}
		}

		return payload;
	}

	public int getHttpCode(ResponseCode coapCode) throws TranslationException {
		Integer httpCode = translationMapping.getHttpCode(coapCode);

		if (httpCode == null) {
			LOGGER.warn("httpCode not defined for {}", coapCode);
			throw new TranslationException("no httpCode for " + coapCode);
		}

		return httpCode;
	}

	public String getHttpMethod(Code coapCode) throws TranslationException {
		return translationMapping.getHttpMethod(coapCode);
	}

	/**
	 * Generates an HTTP entity starting from a CoAP request. If the coap
	 * message has no payload, it returns a null http entity. It takes the
	 * payload from the CoAP message and encapsulates it in an entity. If the
	 * content-type is recognized, and a mapping is present in the properties
	 * file, it is translated to the correspondent in HTTP, otherwise it is set
	 * to application/octet-stream. If the content-type has a charset, namely it
	 * is printable, the payload is encapsulated in a StringEntity, if not it a
	 * ByteArrayEntity is used.
	 * 
	 * 
	 * @param coapMessage the coap message
	 * 
	 * 
	 * @return null if the request has no payload * @throws TranslationException
	 *         the translation exception
	 */
	public HttpEntity getHttpEntity(Message coapMessage) throws TranslationException {
		if (coapMessage == null) {
			throw new IllegalArgumentException("coapMessage == null");
		}

		// the result
		HttpEntity httpEntity = null;

		// check if coap request has a payload
		byte[] payload = coapMessage.getPayload();
		if (payload != null && payload.length != 0) {

			ContentType contentType = null;

			// if the content type is not set, translate with octect-stream
			if (!coapMessage.getOptions().hasContentFormat()) {
				contentType = ContentType.APPLICATION_OCTET_STREAM;
			} else {
				int coapContentType = coapMessage.getOptions().getContentFormat();
				// search for the media type inside the property file
				String coapContentTypeString = translationMapping.getProperty(KEY_COAP_MEDIA + coapContentType);

				// if the content-type has not been found in the property file,
				// try to get its string value (expressed in mime type)
				if (coapContentTypeString == null || coapContentTypeString.isEmpty()) {
					coapContentTypeString = MediaTypeRegistry.toString(coapContentType);

					// if the coap content-type is printable, it is needed to
					// set the default charset (i.e., UTF-8)
					if (MediaTypeRegistry.isPrintable(coapContentType)) {
						coapContentTypeString += "; charset=UTF-8";
					}
				}

				// parse the content type
				try {
					contentType = ContentType.parse(coapContentTypeString);
				} catch (UnsupportedCharsetException e) {
					LOGGER.debug("Cannot convert string to ContentType", e);
					contentType = ContentType.APPLICATION_OCTET_STREAM;
				}
			}

			// get the charset
			Charset charset = contentType.getCharset();

			// if there is a charset, means that the content is not binary
			if (charset != null) {

				// according to the class ContentType the default content-type
				// with UTF-8 charset is application/json. If the content-type
				// parsed is different and is not iso encoded, a translation is
				// needed
				Charset isoCharset = ISO_8859_1;
				if (!charset.equals(isoCharset)
						&& !contentType.getMimeType().equals(ContentType.APPLICATION_JSON.getMimeType())) {
					byte[] newPayload = changeCharset(payload, charset, isoCharset);

					// since ISO-8859-1 is a subset of UTF-8, it is needed to
					// check if the mapping could be accomplished, only if the
					// operation is successful the payload and the charset
					// should
					// be changed
					if (newPayload != null) {
						payload = newPayload;
						// if the charset is changed, also the entire
						// content-type must change
						contentType = ContentType.create(contentType.getMimeType(), isoCharset);
					}
				}

				// create the content
				String payloadString = new String(payload, contentType.getCharset());

				// create the entity
				httpEntity = new StringEntity(payloadString, contentType);
			} else {
				// create the entity
				httpEntity = new ByteArrayEntity(payload);
			}

			// set the content-type
			((AbstractHttpEntity) httpEntity).setContentType(contentType.toString());
		}

		return httpEntity;
	}

	/**
	 * Gets the http headers from a list of CoAP options. The method iterates
	 * over the list looking for a translation of each option in the properties
	 * file, this process ignores the proxy-uri and the content-type because
	 * they are managed differently. If a mapping is present, the content of the
	 * option is mapped to a string accordingly to its original format and set
	 * as the content of the header.
	 * 
	 * 
	 * @param optionList the coap message
	 * 
	 * @return Header[]
	 */
	public Header[] getHttpHeaders(List<Option> optionList) {
		if (optionList == null) {
			throw new IllegalArgumentException("coapMessage == null");
		}

		List<Header> headers = new LinkedList<Header>();

		// iterate over each option
		for (Option option : optionList) {
			// skip content-type because it should be translated while handling
			// the payload; skip proxy-uri because it has to be translated in a
			// different way
			int optionNumber = option.getNumber();
			if (optionNumber != OptionNumberRegistry.CONTENT_FORMAT && optionNumber != OptionNumberRegistry.PROXY_URI) {
				// get the mapping from the property file
				String headerName = translationMapping.getProperty(KEY_COAP_OPTION + optionNumber);

				// set the header
				if (headerName != null && !headerName.isEmpty()) {
					// format the value
					String stringOptionValue = null;
					if (OptionNumberRegistry.getFormatByNr(optionNumber) == optionFormats.STRING) {
						stringOptionValue = option.getStringValue();
					} else if (OptionNumberRegistry.getFormatByNr(optionNumber) == optionFormats.INTEGER) {
						stringOptionValue = Integer.toString(option.getIntegerValue());
					} else if (OptionNumberRegistry.getFormatByNr(optionNumber) == optionFormats.OPAQUE) {
						stringOptionValue = new String(option.getValue());
					} else {
						// if the option is not formattable, skip it
						continue;
					}

					// custom handling for max-age
					// format: cache-control: max-age=60
					if (optionNumber == OptionNumberRegistry.MAX_AGE) {
						stringOptionValue = "max-age=" + stringOptionValue;
					}

					Header header = new BasicHeader(headerName, stringOptionValue);
					headers.add(header);
				}
			}
		}

		return headers.toArray(new Header[0]);
	}

	public Properties getHttpTranslationProperties() {
		return translationMapping;
	}

	/**
	 * Change charset.
	 * 
	 * @param payload the payload
	 * @param fromCharset the from charset
	 * @param toCharset the to charset
	 * 
	 * 
	 * @return the byte[] * @throws TranslationException the translation
	 *         exception
	 */
	public byte[] changeCharset(byte[] payload, Charset fromCharset, Charset toCharset) throws TranslationException {
		try {
			// decode with the source charset
			CharsetDecoder decoder = fromCharset.newDecoder();
			CharBuffer charBuffer = decoder.decode(ByteBuffer.wrap(payload));
			decoder.flush(charBuffer);

			// encode to the destination charset
			CharsetEncoder encoder = toCharset.newEncoder();
			ByteBuffer byteBuffer = encoder.encode(charBuffer);
			encoder.flush(byteBuffer);

			payload  = new byte[byteBuffer.remaining()];
			byteBuffer.get(payload);
		} catch (UnmappableCharacterException e) {
			// thrown when an input character (or byte) sequence is valid but
			// cannot be mapped to an output byte (or character) sequence.
			// If the character sequence starting at the input buffer's current
			// position cannot be mapped to an equivalent byte sequence and the
			// current unmappable-character
			LOGGER.debug("Charset translation: cannot mapped to an output char byte", e);
			return null;
		} catch (CharacterCodingException e) {
			LOGGER.warn("Problem in the decoding/encoding charset", e);
			throw new TranslationException("Problem in the decoding/encoding charset", e);
		}

		return payload;
	}
}
