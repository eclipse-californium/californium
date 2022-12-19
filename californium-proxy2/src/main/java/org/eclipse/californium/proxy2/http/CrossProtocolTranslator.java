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
 *    Bosch IO GmbH - derived from org.eclipse.californium.proxy.HttpTranslator
 ******************************************************************************/
package org.eclipse.californium.proxy2.http;

import static org.eclipse.californium.elements.util.StandardCharsets.ISO_8859_1;
import static org.eclipse.californium.elements.util.StandardCharsets.UTF_8;

import java.net.URI;
import java.net.URISyntaxException;
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

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HeaderElement;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.http.message.BasicHeaderValueParser;
import org.apache.hc.core5.http.message.HeaderValueParser;
import org.apache.hc.core5.http.message.ParserCursor;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.MediaTypeRegistry.MediaTypeDefintion;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionNumberRegistry.OptionFormat;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.option.OptionDefinition;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.proxy2.InvalidMethodException;
import org.eclipse.californium.proxy2.TranslationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class providing the translations (mappings) from the HTTP message artifacts
 * to the CoAP message artifacts and vice versa.
 */
public class CrossProtocolTranslator {

	/**
	 * Property file containing the mappings between coap messages and http
	 * messages.
	 * 
	 * @since 3.0 (adapted to lazy initialization)
	 */
	private static MappingProperties defaultMappingProperties;

	/**
	 * Get default mapping properties.
	 * 
	 * Load mapping properties from default file. On very first execution,
	 * creates also the mapping properties file.
	 * 
	 * @return default mapping properties
	 * @since 3.0
	 */
	private static synchronized MappingProperties getDefaultMappingProperties() {
		if (defaultMappingProperties == null) {
			defaultMappingProperties = new MappingProperties("Proxy2.properties");
		}
		return defaultMappingProperties;
	}

	private final MappingProperties translationMapping;
	private final HeaderValueParser parser = new BasicHeaderValueParser();

	// Error constants
	public static final int STATUS_TIMEOUT = HttpStatus.SC_GATEWAY_TIMEOUT;
	public static final int STATUS_NOT_FOUND = HttpStatus.SC_BAD_GATEWAY;
	public static final int STATUS_TRANSLATION_ERROR = HttpStatus.SC_BAD_GATEWAY;
	public static final int STATUS_URI_MALFORMED = HttpStatus.SC_BAD_REQUEST;
	public static final int STATUS_WRONG_METHOD = HttpStatus.SC_NOT_IMPLEMENTED;
	public static final int STATUS_INTERNAL_SERVER_ERROR = HttpStatus.SC_INTERNAL_SERVER_ERROR;

	private static final Logger LOGGER = LoggerFactory.getLogger(CrossProtocolTranslator.class);

	/**
	 * Creates http translator from properties file.
	 * 
	 * @param mappingPropertiesFileName properties file
	 */
	public CrossProtocolTranslator(String mappingPropertiesFileName) {
		translationMapping = new MappingProperties(mappingPropertiesFileName);
	}

	/**
	 * Creates http translator default properties file.
	 * 
	 * @see #getDefaultMappingProperties()
	 */
	public CrossProtocolTranslator() {
		translationMapping = getDefaultMappingProperties();
	}

	/**
	 * Creates http translator from properties.
	 * 
	 * @param properties properties for translation
	 */
	public CrossProtocolTranslator(MappingProperties properties) {
		translationMapping = properties;
	}

	/**
	 * Convert a http status code into a coap response code.
	 * 
	 * @param coapMethod coap method code
	 * @param httpCode http status code.
	 * @return coap response code
	 * @throws TranslationException if no coap response code maps to the
	 *             provided http status code
	 */
	public ResponseCode getCoapResponseCode(Code coapMethod, int httpCode) throws TranslationException {
		ResponseCode responseCode = translationMapping.getCoapResponseCode(coapMethod, httpCode);

		if (responseCode == null) {
			LOGGER.debug("coap response code missing for {}", httpCode);
			throw new TranslationException("coap response-code missing for " + httpCode + "!");
		}
		return responseCode;
	}

	/**
	 * Convert a http method into a coap request code.
	 * 
	 * @param httpMethod http method
	 * @return coap request code
	 * @throws InvalidMethodException if http method is not supported
	 * @throws NullPointerException if http method is {@code null}
	 * @see MappingProperties#getCoapCode(String)
	 */
	public Code getCoapCode(String httpMethod) throws InvalidMethodException {
		// error handling is implemented in the mapping!
		return translationMapping.getCoapCode(httpMethod);
	}

	/**
	 * Gets the coap media type associated to the http mime type.
	 * 
	 * Firstly, it looks for a valid mapping in the property file. If this step
	 * fails, then it tries to explicitly map/parse the declared mime/type. If
	 * even this step fails, it sets application/octet-stream as content-type.
	 * 
	 * @param mimeType mime-type
	 * @return the coap media code associated to the mime-type.
	 * @throws NullPointerException if mime-type is {@code null}.
	 * @see MediaTypeRegistry
	 */
	public int getCoapMediaType(String mimeType) {
		// if not recognized, the content-type should be
		// application/octet-stream (draft-castellani-core-http-mapping 6.2)
		return getCoapMediaType(mimeType, MediaTypeRegistry.APPLICATION_OCTET_STREAM);
	}

	/**
	 * Gets the coap media type associated to the http mime type.
	 * 
	 * Firstly, it looks for a valid mapping in the property file. If this step
	 * fails, then it tries to explicitly map/parse the declared mime/type. If
	 * even this step fails, it sets the provided default content type.
	 * 
	 * @param mimeType mime-type
	 * @param defaultCoapContentType default, if mime-type could not be mapped.
	 * @return the coap media code associated to the mime-type.
	 * @throws NullPointerException if mime-type is {@code null}.
	 * @see MediaTypeRegistry
	 * @since 3.0
	 */
	public int getCoapMediaType(String mimeType, int defaultCoapContentType) {
		if (mimeType == null) {
			throw new NullPointerException("mime type must not be null!");
		}

		// set the content-type with a default value
		int coapContentType = MediaTypeRegistry.UNDEFINED;

		// delete the last part (if any)
		mimeType = mimeType.split(";")[0].trim();

		// retrieve the mapping from the property file
		Integer coapType = translationMapping.getCoapMediaType(mimeType);
		if (coapType == null) {
			String mimeBaseType = mimeType.split("/")[0].trim();
			coapType = translationMapping.getCoapMediaType(mimeBaseType);
		}
		if (coapType != null) {
			coapContentType = coapType;
		} else {
			// try to parse the media type, if the property file has no mapping
			coapContentType = MediaTypeRegistry.parse(mimeType);
		}

		if (coapContentType == MediaTypeRegistry.UNDEFINED) {
			coapContentType = defaultCoapContentType;
		}

		return coapContentType;
	}

	/**
	 * Gets the coap options starting from an array of http headers.
	 * 
	 * The content-type is not handled by this method. The method iterates over
	 * an array of headers and for each of them tries to find a mapping in the
	 * properties file, if the mapping does not exists it skips the header
	 * ignoring it. The method handles separately certain headers which are
	 * translated to options (such as accept or cache-control) whose content
	 * should be semantically checked or requires ad-hoc translation. Otherwise,
	 * the headers content is translated with the appropriate format required by
	 * the mapped option.
	 * 
	 * @param headers array of http headers
	 * @param etagTranslator translator for etag
	 * @return list of CoAP options.
	 * @throws NullPointerException if headers is {@code null}
	 */
	public List<Option> getCoapOptions(Header[] headers, EtagTranslator etagTranslator) {
		if (headers == null) {
			throw new NullPointerException("http header must not be null!");
		}

		Option accept = null;
		float acceptQualifier = 0.0F;
		List<Option> optionList = new LinkedList<Option>();

		// iterate over the headers
		for (Header header : headers) {
			try {
				String headerName = header.getName().toLowerCase();

				// get the mapping from the property file
				OptionDefinition optionDefinition = translationMapping.getCoapOptionDefinition(headerName);
				// ignore the header if not found in the properties file
				if (optionDefinition == null) {
					continue;
				}
//				int optionNumber = coapOption;
				// ignore the content-type, it will be handled within the payload
				if (optionDefinition.equals(StandardOptionRegistry.CONTENT_FORMAT)) {
					continue;
				}

				// get the value of the current header
				String headerValue = header.getValue().trim();

				// if the option is accept, it needs to translate the values
				if (optionDefinition.equals(StandardOptionRegistry.ACCEPT)) {
					final ParserCursor cursor = new ParserCursor(0, headerValue.length());
					HeaderElement[] headerElements = parser.parseElements(headerValue, cursor);
					for (HeaderElement element : headerElements) {
						float qualifier = 1.0F;
						String mimeType = element.getName();
						NameValuePair q = element.getParameterByName("q");
						if (q != null) {
							try {
								qualifier = Float.parseFloat(q.getValue());
							} catch (NumberFormatException ex) {
							}
						}
						if (accept == null || acceptQualifier < qualifier) {
							int coapContentType = MediaTypeRegistry.UNDEFINED;
							String headerFragment = mimeType.trim();
							if (headerFragment.contains("*")) {
								int[] coapContentTypes = MediaTypeRegistry.parseWildcard(headerFragment);
								if (coapContentTypes.length > 0) {
									coapContentType = coapContentTypes[0];
								}
							} else {
								coapContentType = getCoapMediaType(headerFragment, MediaTypeRegistry.UNDEFINED);
							}
							if (coapContentType != MediaTypeRegistry.UNDEFINED) {
								accept = new Option(StandardOptionRegistry.ACCEPT, coapContentType);
								acceptQualifier = qualifier;
							}
						}
					}
				} else if (optionDefinition.equals(StandardOptionRegistry.MAX_AGE)) {
					int maxAge = -1;
					final ParserCursor cursor = new ParserCursor(0, headerValue.length());
					HeaderElement[] headerElements = parser.parseElements(headerValue, cursor);
					for (HeaderElement element : headerElements) {
						if (element.getName().equalsIgnoreCase("no-cache")) {
							maxAge = 0;
							break;
						} else if (element.getName().equalsIgnoreCase("max-age")) {
							String value = element.getValue();
							try {
								maxAge = Integer.parseInt(value);
								break;
							} catch (NumberFormatException e) {
								LOGGER.debug("Cannot convert cache control '{}' in max-age option", value, e);
							}
						}
					}
					if (maxAge >= 0) {
						// create the option
						Option option = new Option(StandardOptionRegistry.MAX_AGE, maxAge);
						optionList.add(option);
					}
				} else if (optionDefinition.equals(StandardOptionRegistry.ETAG)) {
					byte[] etag = etagTranslator.getCoapEtag(headerValue);
					Option option = new Option(StandardOptionRegistry.ETAG, etag);
					optionList.add(option);
				} else if (optionDefinition.equals(StandardOptionRegistry.IF_MATCH)) {
					byte[] etag = etagTranslator.getCoapEtag(headerValue);
					Option option = new Option(StandardOptionRegistry.IF_MATCH, etag);
					optionList.add(option);
				} else if (optionDefinition.equals(StandardOptionRegistry.IF_NONE_MATCH)) {
					if (headerValue.equals("*")) {
						Option option = new Option(StandardOptionRegistry.IF_NONE_MATCH, Bytes.EMPTY);
						optionList.add(option);
					} else {
						LOGGER.debug("'if-none-match' with etag '{}' is not supported!", headerValue);
					}
				} else if (optionDefinition.equals(StandardOptionRegistry.LOCATION_PATH)) {
					try {
						URI uri = new URI(headerValue);
						OptionSet set = new OptionSet();
						String value = uri.getPath();
						if (value != null) {
							set.setLocationPath(value);
						}
						value = uri.getQuery();
						if (value != null) {
							set.setLocationQuery(value);
						}
						optionList.addAll(set.asSortedList());
					} catch (URISyntaxException e) {
						LOGGER.debug("'content-location' with '{}' is not supported!", headerValue, e);
					} catch (IllegalArgumentException e) {
						LOGGER.debug("'content-location' with '{}' is not supported!", headerValue, e);
					}
				} else {
					// create the option
					Option option = new Option(optionDefinition);
					switch (optionDefinition.getFormat()) {
					case INTEGER:
						option.setIntegerValue(Integer.parseInt(headerValue));
						break;
					case OPAQUE:
						option.setValue(headerValue.getBytes(ISO_8859_1));
						break;
					case EMPTY:
						option.setValue(Bytes.EMPTY);
						break;
					case STRING:
					default:
						option.setStringValue(headerValue);
						break;
					}
					optionList.add(option);
				}
			} catch (RuntimeException e) {
				LOGGER.debug("Could not parse header line {}: {}", header, e.getMessage());
			}
		}
		if (accept != null) {
			optionList.add(accept);
		}
		return optionList;
	}

	/**
	 * Method to map the http entity in a coherent payload for the coap message.
	 * 
	 * The method simply gets the bytes from the entity and, if needed changes
	 * the charset of the obtained bytes to UTF-8.
	 * 
	 * @param httpBody the http entity. May be {@code null} or empty.
	 * @param coapMessage the coap message
	 * @throws TranslationException the translation exception
	 * @throws NullPointerException if the coap-message is {@code null}
	 */
	public void setCoapPayload(ContentTypedEntity httpBody, Message coapMessage) throws TranslationException {
		if (coapMessage == null) {
			throw new NullPointerException("coap message must not be null!");
		}
		if (httpBody != null) {
			byte[] payload = httpBody.getContent();
			if (payload != null) {
				ContentType contentType = httpBody.getContentType();
				String mimeType = contentType.getMimeType();
				int coapContentType = getCoapMediaType(mimeType);
				coapMessage.getOptions().setContentFormat(coapContentType);
				if (MediaTypeRegistry.isCharsetConvertible(coapContentType)) {
					try {

						// get the charset for the http entity
						Charset httpCharset = contentType.getCharset();

						// check if the charset is UTF_8, the only supported by
						// coap
						if (httpCharset != null && !httpCharset.equals(UTF_8)) {
							// translate the payload to the utf-8 charset
							payload = convertCharset(payload, httpCharset, UTF_8);
						}
					} catch (UnsupportedCharsetException e) {
						LOGGER.debug("Cannot get the content of the http entity: " + e.getMessage());
						throw new TranslationException("Cannot get the content of the http entity", e);
					}
				}
				if (payload.length > 256) {
					if (coapMessage instanceof Response) {
						if (!((Response) coapMessage).isSuccess()) {
							if (ContentType.TEXT_HTML.getMimeType().equals(mimeType)) {
								// blockwise is not supported for error responses
								// https://github.com/core-wg/corrclar/issues/25
								// reduce payload size
								String page = new String(payload, UTF_8);
								int start = page.indexOf("<body>");
								if (start >= 0) {
									int end = page.indexOf("</body>", start);
									if (end >= 0) {
										page = page.substring(start + 6, end);
										payload = page.getBytes(UTF_8);
									}
								}
							}
						}
					}
				}
				coapMessage.setPayload(payload);
			}
		}
	}

	/**
	 * Convert a coap response code into a http response code.
	 * 
	 * @param coapCode coap code.
	 * @return http response code
	 * @throws TranslationException if no http response code maps to the
	 *             provided coap code
	 * @throws NullPointerException if coap code is {@code null}
	 */
	public int getHttpCode(ResponseCode coapCode) throws TranslationException {
		if (coapCode == null) {
			throw new NullPointerException("coap response code must not be null!");
		}
		Integer httpCode = translationMapping.getHttpStatusCode(coapCode);

		if (httpCode == null) {
			LOGGER.debug("http code not defined for {}", coapCode);
			throw new TranslationException("no httpCode for " + coapCode);
		}

		return httpCode;
	}

	/**
	 * Convert a coap request code into a http request method.
	 * 
	 * @param coapCode coap code.
	 * @return http request method
	 * @throws TranslationException if no http request method maps to the
	 *             provided coap code
	 * @throws NullPointerException if coap code is {@code null}
	 */
	public String getHttpMethod(Code coapCode) throws TranslationException {
		if (coapCode == null) {
			throw new NullPointerException("coap request code must not be null!");
		}
		String httpMethods = translationMapping.getHttpMethod(coapCode);

		if (httpMethods == null) {
			LOGGER.debug("http method not defined for {}", coapCode);
			throw new TranslationException("no httpCode for " + coapCode);
		}

		return httpMethods;
	}

	/**
	 * Get http content-type from coap content-type.
	 * 
	 * @param coapContentType coap content-type
	 * @return http content-type
	 * @throws TranslationException if no http content-type is available for the
	 *             provided coap content-type
	 */
	public ContentType getHttpContentType(int coapContentType) throws TranslationException {
		String coapContentTypeString = translationMapping.getHttpMimeType(coapContentType);
		if (coapContentTypeString != null && !coapContentTypeString.isEmpty()) {
			try {
				return ContentType.parseLenient(coapContentTypeString);
			} catch (UnsupportedCharsetException e) {
				// actually not used by parseLenient
			}
		} else {
			MediaTypeDefintion definition = MediaTypeRegistry.getDefinition(coapContentType);
			if (definition != null) {
				coapContentTypeString = definition.getMime();
				if (definition.isPrintable()) {
					try {
						return ContentType.create(coapContentTypeString, "UTF-8");
					} catch (UnsupportedCharsetException e) {
						// UTF-8 must be supported!
					}
				} else {
					return ContentType.create(coapContentTypeString);
				}
			}
		}
		throw new TranslationException("CoAP content type " + coapContentType + " not supported!");
	}

	/**
	 * Gets the http headers from a list of CoAP options.
	 * 
	 * The method iterates over the list looking for a translation of each
	 * option in the properties file, this process ignores the proxy-uri and the
	 * content-type because they are managed differently. If a mapping is
	 * present, the content of the option is mapped to a string accordingly to
	 * its original format and set as the content of the header.
	 * 
	 * @param optionList the coap message
	 * @param etagTranslator translator for etag
	 * @return Header[] the http-headers
	 * @throws NullPointerException if the option list is {@code null}
	 */
	public Header[] getHttpHeaders(List<Option> optionList, EtagTranslator etagTranslator) {
		if (optionList == null) {
			throw new NullPointerException("coap options must not be null!");
		}

		boolean hasLocation = false;
		List<Header> headers = new LinkedList<Header>();
		// iterate over each option
		for (Option option : optionList) {
			// skip content-type because it should be translated while handling
			// the payload;
			OptionDefinition definition = option.getDefinition();
			if (StandardOptionRegistry.CONTENT_FORMAT.equals(definition)) {
				continue;
			}
			if (StandardOptionRegistry.LOCATION_PATH.equals(definition)
					|| StandardOptionRegistry.LOCATION_QUERY.equals(definition)) {
				hasLocation = true;
				continue;
			}
			// get the mapping from the property file
			String headerName = translationMapping.getHttpHeader(option.getNumber());

			// set the header
			if (headerName != null && !headerName.isEmpty()) {

				OptionFormat optionFormat = definition.getFormat();
				// format the value
				String stringOptionValue = null;
				if (StandardOptionRegistry.ETAG.equals(definition)) {
					stringOptionValue = etagTranslator.getHttpEtag(option.getValue());
				} else if (StandardOptionRegistry.IF_MATCH.equals(definition)) {
					stringOptionValue = etagTranslator.getHttpEtag(option.getValue());
				} else if (StandardOptionRegistry.IF_NONE_MATCH.equals(definition)) {
					stringOptionValue = "*";
				} else if (StandardOptionRegistry.ACCEPT.equals(definition)) {
					try {
						stringOptionValue = getHttpContentType(option.getIntegerValue()).toString();
					} catch (TranslationException e) {
						continue;
					}
				} else if (optionFormat == OptionFormat.STRING) {
					stringOptionValue = option.getStringValue();
				} else if (optionFormat == OptionFormat.INTEGER) {
					stringOptionValue = Integer.toString(option.getIntegerValue());
				} else if (optionFormat == OptionFormat.OPAQUE) {
					stringOptionValue = new String(option.getValue());
				} else if (optionFormat == OptionFormat.EMPTY) {
					stringOptionValue = "";
				} else {
					// if the option is not formattable, skip it
					continue;
				}

				// custom handling for max-age
				// format: cache-control: max-age=60
				if (StandardOptionRegistry.MAX_AGE.equals(definition)) {
					stringOptionValue = "max-age=" + stringOptionValue;
				}

				Header header = new BasicHeader(headerName, stringOptionValue);
				headers.add(header);
			}
		}
		if (hasLocation) {
			StringBuilder locationPath = new StringBuilder();
			StringBuilder locationQuery = new StringBuilder();
			for (Option option : optionList) {
				OptionDefinition definition = option.getDefinition();
				if (StandardOptionRegistry.LOCATION_PATH.equals(definition)) {
					locationPath.append("/").append(option.getStringValue());
				} else if (StandardOptionRegistry.LOCATION_QUERY.equals(definition)) {
					locationQuery.append("&").append(option.getStringValue());
				}
			}
			if (locationQuery.length() > 0) {
				locationQuery.replace(0, 1, "?");
				locationPath.append(locationQuery);
			}
			String headerName = translationMapping.getHttpHeader(OptionNumberRegistry.LOCATION_PATH);
			Header header = new BasicHeader(headerName, locationPath.toString());
			headers.add(header);
		}
		return headers.toArray(new Header[0]);
	}

	/**
	 * Generates an HTTP entity starting from a CoAP request.
	 * 
	 * If the coap message has no payload, it returns a null http entity. It
	 * takes the payload from the CoAP message and encapsulates it in an entity.
	 * If the content-type is recognized, and a mapping is present in the
	 * properties file, it is translated to the correspondent in HTTP, otherwise
	 * it is set to application/octet-stream. If the content-type has a charset,
	 * namely it is printable, the payload is encapsulated in a StringEntity, if
	 * not it a ByteArrayEntity is used.
	 * 
	 * @param coapMessage the coap message
	 * @return http entity, or {@code null}, if the request has no payload
	 * @throws TranslationException the translation exception
	 * @throws NullPointerException if the coap-message is {@code null}
	 */
	public ContentTypedEntity getHttpEntity(Message coapMessage) throws TranslationException {
		if (coapMessage == null) {
			throw new NullPointerException("coap message must not be null!");
		}

		// the result
		ContentTypedEntity httpEntity = null;

		// check if coap request has a payload
		byte[] payload = coapMessage.getPayload();
		if (payload.length > 0) {

			ContentType contentType = null;
			// if the content type is not set, translate with octect-stream
			if (!coapMessage.getOptions().hasContentFormat()) {
				contentType = ContentType.APPLICATION_OCTET_STREAM;
			} else {
				int coapContentType = coapMessage.getOptions().getContentFormat();
				contentType = getHttpContentType(coapContentType);
				if (MediaTypeRegistry.isCharsetConvertible(coapContentType)) {
					// get the charset
					Charset charset = contentType.getCharset();
					// try to convert to http default ISO_8859_1
					// Just for JSON, keep the original encoding
					if (charset != null && !ISO_8859_1.equals(charset)) {
						byte[] newPayload = convertCharset(payload, charset, ISO_8859_1);
						// since ISO-8859-1 is a subset of UTF-8, it is needed
						// to
						// check if the mapping could be accomplished, only if
						// the
						// operation is successful the payload and the charset
						// should be changed
						if (newPayload != null) {
							payload = newPayload;
							// if the charset is changed, also the entire
							// content-type must change
							contentType = contentType.withCharset(ISO_8859_1);
						}
					}
				}
			}
			// create the entity
			httpEntity = new ContentTypedEntity(contentType, payload);
		}

		return httpEntity;
	}

	/**
	 * Get properties used for translation.
	 * 
	 * @return properties for translation
	 */
	public Properties getHttpTranslationProperties() {
		return translationMapping;
	}

	/**
	 * Convert payload changing the charset.
	 * 
	 * @param payload the payload
	 * @param fromCharset the from charset
	 * @param toCharset the to charset
	 * @return the converted payload. {@code null}, if the provided payload
	 *         didn't comply to the source charset.
	 * @throws TranslationException the translation exception
	 */
	public byte[] convertCharset(byte[] payload, Charset fromCharset, Charset toCharset) throws TranslationException {
		try {
			// decode with the source charset
			CharsetDecoder decoder = fromCharset.newDecoder();
			CharBuffer charBuffer = decoder.decode(ByteBuffer.wrap(payload));
			decoder.flush(charBuffer);
			// encode to the destination charset
			CharsetEncoder encoder = toCharset.newEncoder();
			ByteBuffer byteBuffer = encoder.encode(charBuffer);
			encoder.flush(byteBuffer);
			payload = new byte[byteBuffer.remaining()];
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

	/**
	 * Converts http textual etag and coap binary etag.
	 * 
	 * @since 3.0
	 */
	public static interface EtagTranslator {

		/**
		 * Convert http textual etag to coap binary etag.
		 * 
		 * @param value textual etag
		 * @return binary etag
		 * @throws IllegalArgumentException if etag can not be converted
		 */
		public byte[] getCoapEtag(String value);

		/**
		 * Convert coap binary etag to http textual etag.
		 * 
		 * @param value binary etag
		 * @return textual etag
		 * @throws IllegalArgumentException if etag can not be converted
		 */
		public String getHttpEtag(byte[] value);

	}

	/**
	 * Converts coap binary etag emitted by a coap server.
	 * 
	 * The etag is processed as binary of maximum 8 bytes and is converted into
	 * hexadecimal representation.
	 * 
	 * @since 3.0
	 */
	public static class CoapServerEtagTranslator implements EtagTranslator {

		@Override
		public byte[] getCoapEtag(String value) {
			byte[] etag = StringUtil.hex2ByteArray(value);
			StandardOptionRegistry.ETAG.assertValue(etag);
			return etag;
		}

		@Override
		public String getHttpEtag(byte[] value) {
			return StringUtil.byteArray2Hex(value);
		}

	}

	/**
	 * Converts http textual etag emitted by a http server.
	 * 
	 * The etag is processed as ASCII text encoded as bytes with a maximum of 8
	 * characters.
	 * 
	 * @since 3.0
	 */
	public static class HttpServerEtagTranslator implements EtagTranslator {

		@Override
		public byte[] getCoapEtag(String value) {
			byte[] etag = value.getBytes(ISO_8859_1);
			StandardOptionRegistry.ETAG.assertValue(etag);
			return etag;
		}

		@Override
		public String getHttpEtag(byte[] value) {
			return new String(value, ISO_8859_1);
		}

	}

}
