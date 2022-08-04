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
package org.eclipse.californium.cloud.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.security.auth.DestroyFailedException;

import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.util.Asn1DerDecoder;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.JceProviderUtil;
import org.eclipse.californium.elements.util.StandardCharsets;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Device credentials parser.
 * 
 * Format:
 * 
 * <pre>
 * {@code # <comment>}
 * {@code <device-name>[.group]=<group>}
 * {@code [[<device-name>].psk=<identity>,<pre-shared-secret>]}
 * {@code [[<device-name>].rpk=<raw-public-key-certificate>]}
 * </pre>
 * 
 * The {@code identity} may be included in single- ({@code '}) or double-quotes
 * ({@code "}). The {@code pre-shared-secret} may be provided in base 64
 * encoding, in hexadecimal encoding with leading {@code :x0}, or as plain text
 * in single- ({@code '}) or double-quotes ({@code "}). The
 * {@code raw-public-key-certificate} may be provided in base 64 encoding, or in
 * hexadecimal encoding with leading {@code :x0}. The
 * {@code raw-public-key-certificate} must be given in ASN.1/PEM format (public
 * key including the algorithm and curve identifier). Only for the
 * {@code secp256r1} curve the public key may be provided as the plain 64 bytes
 * of the public key.
 * 
 * Example:
 * 
 * <pre>
 * {@code # base64 secret}
 * {@code
 * DemoClient = Demo
 * }
 * {@code .psk='Client_identity',c2VjcmV0UFNL}
 * {@code .rpk=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQxYO5/M5ie6+3QPOaAy5MD6CkFILZwIb2rOBCX/EWPaocX1H+eynUnaEEbmqxeN6rnI/pH19j4PtsegfHLrzzQ==}
 * 
 * {@code # PSK only, hexadecimal secret}
 * {@code
 * DemoDevice1 = Demo
 * }
 * {@code .psk='Device_identity',:0x010203040506}
 * 
 * {@code # RPK only, base64 certificate}
 * {@code
 * DemoDevice2 = Demo
 * }
 * {@code .rpk=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVsbICzKorORkRD2BOdZSVnDpsaQ8FePXH0/5vWDspCOwNl8rYPWdmm1ysTpkjA9tjdw2fgYpiBiOzZ3km39eCA==}
 * 
 * </pre>
 * 
 * @since 3.12
 */
public class DeviceParser implements ResourceParser<DeviceParser> {

	private static final Logger LOGGER = LoggerFactory.getLogger(DeviceParser.class);

	/**
	 * ASN.1 header for plain {@code secp256r1} public key.
	 */
	private static final byte[] ECC_SECP256R1_HEADER;

	static {
		// initialize header for secp256r1
		byte[] header = null;
		try {
			String oid = JceProviderUtil.getEdDsaStandardAlgorithmName("EC", "EC");
			KeyPairGenerator generator = KeyPairGenerator.getInstance(oid);
			generator.initialize(new ECGenParameterSpec("secp256r1"), RandomManager.currentSecureRandom());
			KeyPair keyPair = generator.generateKeyPair();
			byte[] encoded = keyPair.getPublic().getEncoded();
			header = Arrays.copyOf(encoded, encoded.length - 64);
		} catch (GeneralSecurityException ex) {
			header = null;
			LOGGER.error("EC failed!", ex);
		}
		ECC_SECP256R1_HEADER = header;
	}

	/**
	 * Device credentials.
	 */
	public static class Device {

		/**
		 * Device name.
		 */
		public final String name;
		/**
		 * Device group.
		 */
		public final String group;
		/**
		 * PreSharedKey identity. {@code null}, if no PreSharedKey credentials
		 * are used.
		 */
		public final String pskIdentity;
		/**
		 * PreSharedKey secret. {@code null}, if no PreSharedKey credentials are
		 * used.
		 */
		public final byte[] pskSecret;
		/**
		 * RawPublicKey certificate. {@code null}, if no RawPublicKey
		 * certificate is used.
		 */
		public final PublicKey publicKey;

		/**
		 * Create service credentials.
		 * 
		 * @param name name of device
		 * @param group group of device
		 * @param pskIdentity PreSharedKey identity. {@code null}, if no
		 *            PreSharedKey credentials are used.
		 * @param pskSecret PreSharedKey secret. {@code null}, if no
		 *            PreSharedKey credentials are used.
		 * @param publicKey RawPublicKey certificate. {@code null}, if no
		 *            RawPublicKey certificate is used.
		 * @throws NullPointerException if name or group is {@code null}, or
		 *             neither valid psk nor rpk credentials are provided.
		 */
		public Device(String name, String group, String pskIdentity, byte[] pskSecret, PublicKey publicKey) {
			if (name == null) {
				throw new NullPointerException("name must not be null!");
			}
			if (group == null) {
				throw new NullPointerException("group must not be null!");
			}
			if (pskIdentity == null && publicKey == null) {
				throw new NullPointerException("Either pskIdentity or publicKey must not be null!");
			}
			if (pskIdentity != null && pskSecret == null) {
				throw new NullPointerException("pskSecret must not be null, if pskIdentity is provided!");
			}
			this.name = name;
			this.pskIdentity = pskIdentity;
			this.pskSecret = pskSecret;
			this.publicKey = publicKey;
			this.group = group;
		}

		@Override
		public int hashCode() {
			return name.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			Device other = (Device) obj;
			if (!name.equals(other.name))
				return false;
			return true;
		}

		/**
		 * Create builder for {@link Device}.
		 * 
		 * @return builder.
		 */
		public static Builder builder() {
			return new Builder();
		}

		/**
		 * Builder for Device.
		 */
		public static class Builder {

			/**
			 * Device name.
			 */
			public String name;
			/**
			 * Device group.
			 */
			public String group;
			/**
			 * PreSharedKey identity. {@code null}, if no PreSharedKey
			 * credentials are used.
			 */
			public String pskIdentity;
			/**
			 * PreSharedKey secret. {@code null}, if no PreSharedKey credentials
			 * are used.
			 */
			public byte[] pskSecret;
			/**
			 * RawPublicKey certificate. {@code null}, if no RawPublicKey
			 * certificate is used.
			 */
			public PublicKey publicKey;

			/**
			 * Create builder.
			 */
			private Builder() {

			}

			/**
			 * Create device from builder data.
			 * 
			 * @return created device
			 */
			public Device build() {
				return new Device(name, group, pskIdentity, pskSecret, publicKey);
			}
		}
	}

	/**
	 * Postfix in header for group.
	 */
	public static final String GROUP_POSTFIX = ".group";
	/**
	 * Postfix in header for PreSharedKey credentials.
	 */
	public static final String PSK_POSTFIX = ".psk";
	/**
	 * Postfix in header for RawPublicKey certificate.
	 */
	public static final String RPK_POSTFIX = ".rpk";

	/**
	 * Map of device names and credentials.
	 */
	private final ConcurrentMap<String, Device> map = new ConcurrentHashMap<>();
	/**
	 * Map of PreSharedKey identities and credentials.
	 */
	private final ConcurrentMap<String, Device> psk = new ConcurrentHashMap<>();
	/**
	 * Map of RawPublicKeys and credentials.
	 */
	private final ConcurrentMap<PublicKey, Device> rpk = new ConcurrentHashMap<>();
	/**
	 * Map of group names and sets of device names.
	 */
	private final ConcurrentMap<String, Set<String>> groups = new ConcurrentHashMap<>();
	/**
	 * {@code true} to use case sensitive names, {@code false}, otherwise.
	 */
	private final boolean caseSensitiveNames;
	/**
	 * {@code true} if credentials are destroyed.
	 */
	private volatile boolean destroyed;

	/**
	 * Create device store.
	 * 
	 * @param caseSensitiveNames {@code true} to use case sensitive names,
	 *            {@code false}, otherwise.
	 */
	public DeviceParser(boolean caseSensitiveNames) {
		this.caseSensitiveNames = caseSensitiveNames;
	}

	/**
	 * Get key from name.
	 * 
	 * @param name name of entry
	 * @return key from name
	 * @see #caseSensitiveNames
	 */
	private String getKey(String name) {
		String key = name == null ? "" : name;
		if (!caseSensitiveNames && key != null) {
			key = key.toLowerCase();
		}
		return key;
	}

	/**
	 * Match names considering {@link #caseSensitiveNames}.
	 * 
	 * @param name1 first name to match
	 * @param name2 second name to match
	 * @return {@code true}, if names are matching, {@code false}, otherwise.
	 */
	private boolean match(String name1, String name2) {
		if (caseSensitiveNames) {
			return name1.equals(name2);
		} else {
			return name1.equalsIgnoreCase(name2);
		}
	}

	/**
	 * Get prefix from id.
	 * 
	 * @param id id
	 * @param postfix postfix to be removed from id
	 * @return either the unchanged id, or the id with the postfix tail removed.
	 * @see StringUtil#truncateTail(boolean, String, String)
	 */
	private String prefix(String id, String postfix) {
		return StringUtil.truncateTail(caseSensitiveNames, id, postfix);
	}

	/**
	 * Checks, if id is a name.
	 * 
	 * The id is a name, if it ends with {@link #GROUP_POSTFIX}, or if it
	 * doesn't end with {@link #PSK_POSTFIX} nor {@link #RPK_POSTFIX}.
	 * 
	 * @param id id to check
	 * @return {@code true}, if id complies with a name, {@code false},
	 *         otherwise.
	 */
	private boolean isName(String id) {
		String name = prefix(id, GROUP_POSTFIX);
		if (name != id) {
			return true;
		}
		name = prefix(id, PSK_POSTFIX);
		if (name != id) {
			return false;
		}
		name = prefix(id, RPK_POSTFIX);
		if (name != id) {
			return false;
		}
		return true;
	}

	/**
	 * Match the device builder with the provided name
	 * 
	 * A device builder without a name doesn't match at all. A empty name
	 * matches any non empty builder name. Or the name must match the builder's
	 * name according {@link #match(String, String)}.
	 * 
	 * @param builder device builder
	 * @param name name
	 * @return {@code true}, if the builder and name matches, {@code false},
	 *         otherwise.
	 */
	private boolean match(Device.Builder builder, String name) {
		if (builder.name == null) {
			return false;
		}
		if (name.isEmpty()) {
			return !builder.name.isEmpty();
		} else {
			return match(builder.name, name);
		}
	}

	/**
	 * Add device from builder credentials.
	 * 
	 * @param builder builder with device data
	 * @return {@code true}, if device was added, {@code false}, if the device
	 *         was already added
	 */
	public boolean add(Device.Builder builder) {
		return add(builder.build());
	}

	/**
	 * Add device.
	 * 
	 * @param device device to add
	 * @return {@code true}, if device was added, {@code false}, if the device
	 *         was already added
	 */
	public boolean add(Device device) {
		String key = getKey(device.name);
		if (map.putIfAbsent(key, device) == null) {
			Device previous = null;
			if (device.pskIdentity != null && (previous = psk.putIfAbsent(device.pskIdentity, device)) != null) {
				LOGGER.info("psk {} {} ambiguous {}", device.pskIdentity, device.name, previous.name);
				map.remove(key, device);
				return false;
			}
			if (device.publicKey != null && (previous = rpk.putIfAbsent(device.publicKey, device)) != null) {
				LOGGER.info("rpk {} ambiguous {}", device.name, previous.name);
				remove(device);
				return false;
			}
			LOGGER.info("added {} {} {}", device.name, device.pskIdentity != null ? "psk" : "",
					device.publicKey != null ? "rpk" : "");
			Set<String> group = new HashSet<>();
			Set<String> prev = groups.putIfAbsent(device.group, group);
			if (prev != null) {
				group = prev;
			}
			group.add(device.name);
			return true;
		}
		return false;
	}

	/**
	 * Get devices of group
	 * 
	 * @param group group
	 * @return set of device names
	 */
	public Set<String> getGroup(String group) {

		Set<String> devices = groups.get(group);
		if (devices == null) {
			devices = Collections.emptySet();
		}
		return devices;
	}

	/**
	 * Get device.
	 * 
	 * @param name device
	 * @return device credentials, or {@code null}, if not available.
	 */
	public Device get(String name) {
		return map.get(getKey(name));
	}

	/**
	 * Get device by PreSharedKey identity.
	 * 
	 * @param identity PreSharedKey identity
	 * @return device credentials, or {@code null}, if not available.
	 */
	public Device getByPreSharedKeyIdentity(String identity) {
		return psk.get(identity);
	}

	/**
	 * Get device by raw public key.
	 * 
	 * @param publicKey raw public key
	 * @return device credentials, or {@code null}, if not available.
	 */
	public Device getByRawPublicKey(PublicKey publicKey) {
		return rpk.get(publicKey);
	}

	/**
	 * Get device by principal.
	 * 
	 * @param principal device principal
	 * @return device credentials, or {@code null}, if not available.
	 * @see #getByPreSharedKeyIdentity(String)
	 * @see #getByRawPublicKey(PublicKey)
	 */
	public Device getByPrincipal(Principal principal) {
		if (principal instanceof PreSharedKeyIdentity) {
			PreSharedKeyIdentity pskIdentity = (PreSharedKeyIdentity) principal;
			return getByPreSharedKeyIdentity(pskIdentity.getIdentity());
		} else if (principal instanceof RawPublicKeyIdentity) {
			RawPublicKeyIdentity rpkIdentity = (RawPublicKeyIdentity) principal;
			return getByRawPublicKey(rpkIdentity.getKey());
		} else if (principal instanceof X509CertPath) {
		}
		return null;
	}

	/**
	 * Remove device.
	 * 
	 * @param name device name
	 * @return {@code true}, if device was removed, {@code false} otherwise.
	 */
	public boolean remove(String name) {
		return remove(get(name));
	}

	/**
	 * Remove device.
	 * 
	 * @param device device to remove
	 * @return {@code true}, if device was removed, {@code false} otherwise.
	 */
	public boolean remove(Device device) {
		boolean removed = map.remove(getKey(device.name), device);
		if (removed) {
			if (device.pskIdentity != null) {
				psk.remove(device.pskIdentity, device);
			}
			if (device.publicKey != null) {
				rpk.remove(device.publicKey, device);
			}
			Set<String> group = groups.get(device.group);
			if (group != null) {
				group.remove(device.name);
			}
			return true;
		}
		return removed;
	}

	/**
	 * Number of entries.
	 * 
	 * @return number of entries
	 */
	public int size() {
		return map.size();
	}

	@Override
	public void save(Writer writer) throws IOException {
		List<String> names = new ArrayList<>(map.keySet());
		Collections.sort(names);
		for (String name : names) {
			Device credentials = map.get(name);
			if (credentials != null) {
				writer.write(credentials.name);
				writer.write('=');
				writer.write(credentials.group);
				writer.write(StringUtil.lineSeparator());
				if (credentials.pskIdentity != null && credentials.pskSecret != null) {
					writer.write(credentials.name + PSK_POSTFIX);
					writer.write('=');
					writer.write(credentials.pskIdentity);
					writer.write(',');
					writer.write(encode64(credentials.pskSecret));
					writer.write(StringUtil.lineSeparator());
				}
				if (credentials.publicKey != null) {
					writer.write(credentials.name + RPK_POSTFIX);
					writer.write('=');
					writer.write(encode64(credentials.publicKey.getEncoded()));
					writer.write(StringUtil.lineSeparator());
				}
			}
		}
	}

	@Override
	public void load(Reader reader) throws IOException {
		BufferedReader lineReader = new BufferedReader(reader);
		try {
			int lineNumber = 0;
			int errors = 0;
			int comments = 0;
			Device.Builder builder = Device.builder();

			String line;
			// readLine() reads the secret into a String,
			// what may be considered to be a weak practice.
			while ((line = lineReader.readLine()) != null) {
				++lineNumber;
				try {
					if (!line.isEmpty() && !line.startsWith("#")) {
						String[] entry = line.split("=", 2);
						if (entry.length == 2) {
							String name = entry[0];
							String[] values = entry[1].split(",");
							String prefix = prefix(name, RPK_POSTFIX);
							if (prefix != name) {
								if (!parseRPK(builder, prefix, values)) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								}
								continue;
							}
							prefix = prefix(name, PSK_POSTFIX);
							if (prefix != name) {
								if (!parsePSK(builder, prefix, values)) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								}
								continue;
							}
							prefix = prefix(name, GROUP_POSTFIX);
							if (prefix != name || isName(name)) {
								if (builder.name != null) {
									add(builder);
									builder = Device.builder();
								}
								if (values.length != 1) {
									++errors;
									LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
								} else {
									if (prefix == null) {
										builder.name = name;
									} else {
										builder.name = prefix;
									}
									builder.group = decodeText(values[0]);
								}
							}
						} else {
							++errors;
							LOGGER.warn("{}: '{}' invalid line!", lineNumber, line);
						}
					} else {
						++comments;
					}
				} catch (IllegalArgumentException ex) {
					++errors;
					LOGGER.warn("{}: '{}' invalid line!", lineNumber, line, ex);
				}
			}
			if (builder.name != null) {
				add(builder);
			}
			if (size() == 0 && errors > 0 && lineNumber == comments + errors) {
				LOGGER.warn("read store, only errors, wrong password?");
				SecretUtil.destroy(this);
			}
		} catch (RuntimeException e) {
			LOGGER.warn("read store, unexpected error occurred!", e);
		} catch (IOException e) {
			if (e.getCause() instanceof GeneralSecurityException) {
				LOGGER.warn("read store, wrong password?", e);
				SecretUtil.destroy(this);
			} else {
				throw e;
			}
		} finally {
			try {
				lineReader.close();
			} catch (IOException e) {
			}
		}
		LOGGER.info("read {} device credentials.", size());
	}

	/**
	 * Parse PreSharedKey credentials.
	 * 
	 * The values must contain the identity in the first and the secret in the
	 * second value.
	 * 
	 * @param builder builder with device data
	 * @param name name part of line
	 * @param values split values of line
	 * @return {@code true} if the PreSharedKey credentials are valid,
	 *         {@code false}, otherwise.
	 */
	private boolean parsePSK(Device.Builder builder, String name, String[] values) {
		if (values.length != 2 || !match(builder, name)) {
			return false;
		}
		builder.pskIdentity = decodeText(values[0]);
		builder.pskSecret = binDecodeTextOr64(values[1]);
		return !builder.pskIdentity.isEmpty() && builder.pskSecret.length > 0;
	}

	/**
	 * Parse RawPublicKey.
	 * 
	 * The values must contain the public key in the first value.
	 * 
	 * @param builder builder with device data
	 * @param name name part of line
	 * @param values split values of line
	 * @return {@code true} if the RawPublicKey is valid, {@code false},
	 *         otherwise.
	 */
	private boolean parseRPK(Device.Builder builder, String name, String[] values) {
		if (values.length != 1 || !match(builder, name)) {
			return false;
		}
		byte[] publicKey = binDecodeTextOr64(values[0]);
		Throwable error = null;
		try {
			builder.publicKey = Asn1DerDecoder.readSubjectPublicKey(publicKey);
			return true;
		} catch (GeneralSecurityException e) {
			error = e;
		} catch (IllegalArgumentException e) {
			error = e;
		}
		if (error != null) {
			if (publicKey.length == 64) {
				publicKey = Bytes.concatenate(ECC_SECP256R1_HEADER, publicKey);
				try {
					builder.publicKey = Asn1DerDecoder.readSubjectPublicKey(publicKey);
					return true;
				} catch (GeneralSecurityException i) {
				} catch (IllegalArgumentException e) {
				}
			}
			LOGGER.warn("RPK:", error);
		}
		return false;
	}

	@Override
	public void destroy() throws DestroyFailedException {
		map.clear();
		destroyed = true;
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

	/**
	 * Encode byte array in base 64.
	 * 
	 * @param value byte array
	 * @return base 64
	 */
	private static String encode64(byte[] value) {
		return StringUtil.byteArrayToBase64(value);
	}

	/**
	 * Decode value to byte array.
	 * 
	 * A plain text value must be in single- ({@code '}) or double-quotes
	 * ({@code "}). A hexadecimal value starts with {@code :0x}. Other values
	 * are considered to be base 64 encoded.
	 * 
	 * @param value value to be decoded
	 * @return byte array
	 */
	private static byte[] binDecodeTextOr64(String value) {
		if (value.isEmpty()) {
			return Bytes.EMPTY;
		}
		char c = value.charAt(0);
		if (c == '\'' || c == '"') {
			if (value.length() > 2) {
				int end = value.length() - 1;
				char e = value.charAt(end);
				if (e == c) {
					value = value.substring(1, end);
					return value.getBytes(StandardCharsets.UTF_8);
				}
			}
		} else if (c == ':') {
			if (value.startsWith(":0x")) {
				return StringUtil.hex2ByteArray(value.substring(3));
			}
		}
		return StringUtil.base64ToByteArray(value);
	}

	/**
	 * Decode text value.
	 * 
	 * If the value is in single- ({@code '}) or double-quotes ({@code "}),
	 * these are removed.
	 * 
	 * @param value value to be decoded
	 * @return text value
	 */
	private static String decodeText(String value) {
		if (!value.isEmpty()) {
			char c = value.charAt(0);
			if (value.length() > 2 && (c == '\'' || c == '"')) {
				int end = value.length() - 1;
				char e = value.charAt(end);
				if (e == c) {
					value = value.substring(1, end);
				}
			}
		}
		return value;
	}

	@Override
	public DeviceParser create() {
		return new DeviceParser(caseSensitiveNames);
	}

}
