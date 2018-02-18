package org.eclipse.californium.scandium.auth;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Principal;

import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;

/**
 * A helper for serializing and deserializing principals supported by Scandium.
 */
public final class PrincipalSerializer {

	private PrincipalSerializer() {
	}

	/**
	 * Serializes a principal to a byte array based on the plain text encoding defined in
	 * <a href="https://tools.ietf.org/html/rfc5077#section-4">RFC 5077, Section 4</a>.
	 * <p>
	 * RFC 5077 does not explicitly define support for RawPublicKey based client authentication.
	 * However, it supports the addition of arbitrary authentication mechanisms by extending
	 * the <em>ClientAuthenticationType</em> which we do as follows: 
	 * <pre>
	 * enum {
	 *   anonymous(0),
	 *   certificate_based(1),
	 *   psk(2),
	 *   raw_public_key(255)
	 * } ClientAuthenticationType
	 * 
	 * struct {
	 *   ClientAuthenticationType client_authentication_type;
	 *   select (ClientAuthenticationType) {
	 *     case anonymous: struct {};
	 *     case certificate_based:
	 *       ASN.1Cert certificate_list<0..2^24-1>;
	 *     case psk:
	 *       opaque psk_identity<0..2^16-1>;
	 *     case raw_public_key:
	 *       opaque ASN.1_subjectPublicKeyInfo<1..2^24-1>; // as defined in RFC 7250
	 *   };
	 * }
	 * </pre>
	 * 
	 * @param principal The principal to serialize.
	 * @param writer The writer to serialize to.
	 * @throws NullPointerException if the writer is {@code null}.
	 */
	public static void serialize(final Principal principal, final DatagramWriter writer) {
		if (writer == null) {
			throw new NullPointerException("Writer must not be null");
		} else if (principal == null) {
			writer.writeByte(ClientAuthenticationType.ANONYMOUS.code);
		} else if (principal instanceof PreSharedKeyIdentity) {
			serializeIdentity((PreSharedKeyIdentity) principal, writer);
		} else if (principal instanceof RawPublicKeyIdentity) {
			serializeSubjectInfo((RawPublicKeyIdentity) principal, writer);
		} else if (principal instanceof X509CertPath) {
			serializeCertChain((X509CertPath) principal, writer);
		} else {
			throw new IllegalArgumentException("unsupported principal type: " + principal.getClass().getName());
		}
	}

	private static void serializeIdentity(final PreSharedKeyIdentity principal, final DatagramWriter writer) {
		writer.writeByte(ClientAuthenticationType.PSK.code);
		writeBytes(principal.getName().getBytes(StandardCharsets.UTF_8), writer);
	}

	private static void serializeSubjectInfo(final RawPublicKeyIdentity principal, final DatagramWriter writer) {
		writer.writeByte(ClientAuthenticationType.RPK.code);
		writeBytes(principal.getSubjectInfo(), writer);
	}

	private static void serializeCertChain(final X509CertPath principal, final DatagramWriter writer) {
		writer.writeByte(ClientAuthenticationType.CERT.code);
		writeBytes(principal.toByteArray(), writer);
	}

	private static void writeBytes(final byte[] bytesToWrite, final DatagramWriter writer) {
		writer.write(bytesToWrite.length, 16);
		writer.writeBytes(bytesToWrite);
	}

	/**
	 * Deserializes a principal from its byte array representation.
	 * 
	 * @param reader The reader containing the byte array.
	 * @return The principal object or {@code null} if the reader does not contain a supported principal type.
	 * @throws GeneralSecurityException if the reader contains a raw public key principal that could not be recreated.
	 * @throws IllegalArgumentException if the reader contains an unsupported ClientAuthenticationType.
	 */
	public static Principal deserialize(final DatagramReader reader) throws GeneralSecurityException {
		if (reader == null) {
			throw new NullPointerException("reader must not be null");
		}
		int code = reader.read(8);
		ClientAuthenticationType type = ClientAuthenticationType.fromCode((byte) code);
		switch(type) {
		case CERT:
			return deserializeCertChain(reader);
		case PSK:
			return deserializeIdentity(reader);
		case RPK:
			return deserializeSubjectInfo(reader);
		default:
			// ANONYMOUS
			return null;
		}
	}

	private static X509CertPath deserializeCertChain(final DatagramReader reader) {
		return X509CertPath.fromBytes(readBytes(reader, 24));
	};

	private static PreSharedKeyIdentity deserializeIdentity(final DatagramReader reader) {
		return new PreSharedKeyIdentity(new String(readBytes(reader, 16)));
	};

	private static RawPublicKeyIdentity deserializeSubjectInfo(final DatagramReader reader) throws GeneralSecurityException {
		byte[] subjectInfo = readBytes(reader, 16);
		return new RawPublicKeyIdentity(subjectInfo);
	}

	private static byte[] readBytes(final DatagramReader reader, final int lengthBits) {
		int length = reader.read(lengthBits);
		return reader.readBytes(length);
	}

	private enum ClientAuthenticationType {

		ANONYMOUS((byte) 0x00),
		CERT((byte) 0x01),
		PSK((byte) 0x02),
		RPK((byte) 0xff);

		private byte code;

		private ClientAuthenticationType(final byte code) {
			this.code = code;
		}

		static ClientAuthenticationType fromCode(final byte code) {
			for (ClientAuthenticationType type : values()) {
				if (type.code == code) {
					return type;
				}
			}
			throw new IllegalArgumentException("unknown ClientAuthenticationType: " + code);
		}
	}
}
