/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Certificate Path Utility.
 * <p>
 * Generates certificate path, check intended certificates usage and verify
 * certificate paths.
 * 
 * This implementation considers the below listed RFC's by:
 * <dl>
 * <dt>self-signed top-level certificate</dt>
 * <dd>Self-signed top-level certificate are removed before validation. This is
 * done before sending such a certificate path and before validating a received
 * certificate path in order to support peers, which doesn't remove it.</dd>
 * <dt>intermediate authorities certificate</dt>
 * <dd>Intermediate authorities certificate are removed before validation. This
 * is done before sending such a certificate path, when a certificate
 * authorities list was received before, and before validating a received
 * certificate path in order to support peers, which doesn't remove them.</dd>
 * </dl>
 * 
 * References:
 * <a href="https://tools.ietf.org/html/rfc5246#section-7.4.2">RFC5246, Section
 * 7.4.2, Server Certificate</a>
 * <p>
 * "Because certificate validation requires that root keys be distributed
 * independently, the self-signed certificate that specifies the root
 * certificate authority MAY be omitted from the chain, under the assumption
 * that the remote end must already possess it in order to validate it in any
 * case."
 * </p>
 * 
 * <a href="http://tools.ietf.org/html/rfc5246#section-7.4.6">RFC5246, Section
 * 7.4.6, Client Certificate </a>
 * <p>
 * "If the certificate_authorities list in the certificate request message was
 * non-empty, one of the certificates in the certificate chain SHOULD be issued
 * by one of the listed CAs."
 * </p>
 * 
 * <a href="https://tools.ietf.org/html/rfc5280#section-6">RFC5280, Section 6,
 * Certification Path Validation</a>
 * <p>
 * "Valid paths begin with certificates issued by a trust anchor." ... "The
 * procedure performed to obtain this sequence of certificates is outside the
 * scope of this specification".
 * </p>
 * @since 2.1
 */
public class CertPathUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(CertPathUtil.class);

	private static final String TYPE_X509 = "X.509";

	/**
	 * OID for server authentication in extended key.
	 */
	private static final String SERVER_AUTHENTICATION = "1.3.6.1.5.5.7.3.1";

	/**
	 * OID for client authentication in extended key.
	 */
	private static final String CLIENT_AUTHENTICATION = "1.3.6.1.5.5.7.3.2";

	/**
	 * Bit for digital signature in key usage.
	 */
	private static final int KEY_USAGE_SIGNATURE = 0;

	/**
	 * Bit for certificate signing in key usage.
	 */
	private static final int KEY_USAGE_CERTIFICATE_SIGNING = 5;

	/**
	 * Check, if certificate is intended to be used to verify a signature of an
	 * other certificate.
	 * 
	 * @param cert certificate to check.
	 * @return {@code true}, if certificate is intended to be used to verify a
	 *         signature of an other certificate, {@code false}, otherwise.
	 */
	public static boolean canBeUsedToVerifySignature(X509Certificate cert) {

		if (cert.getBasicConstraints() < 0) {
			LOGGER.debug("certificate: {}, not for CA!", cert.getSubjectDN());
			return false;
		}
		if ((cert.getKeyUsage() != null && !cert.getKeyUsage()[KEY_USAGE_CERTIFICATE_SIGNING])) {
			LOGGER.debug("certificate: {}, not for certificate signing!", cert.getSubjectDN());
			return false;
		}
		return true;
	}

	/**
	 * Check, if certificate is intended to be used for client or server
	 * authentication.
	 * 
	 * @param cert certificate to check.
	 * @param client {@code true} for client authentication, {@code false} for
	 *            server authentication.
	 * @return {@code true}, if certificate is intended to be used for client or
	 *         server authentication, {@code false}, otherwise.
	 */
	public static boolean canBeUsedForAuthentication(X509Certificate cert, boolean client) {

		// KeyUsage is an optional extension which may be used to restrict
		// the way the key can be used.
		// https://tools.ietf.org/html/rfc5280#section-4.2.1.3
		// If this extension is used, we check if digitalsignature usage is
		// present.
		// (For more details see:
		// https://github.com/eclipse/californium/issues/748)
		if ((cert.getKeyUsage() != null && !cert.getKeyUsage()[KEY_USAGE_SIGNATURE])) {
			LOGGER.debug("certificate: {}, not for signing!", cert.getSubjectDN());
			return false;
		}
		try {
			List<String> list = cert.getExtendedKeyUsage();
			if (list != null && !list.isEmpty()) {
				LOGGER.trace("certificate: {}", cert.getSubjectDN());
				final String authentication = client ? CLIENT_AUTHENTICATION : SERVER_AUTHENTICATION;
				boolean foundUsage = false;
				for (String extension : list) {
					LOGGER.trace("   extkeyusage {}", extension);
					if (authentication.equals(extension)) {
						foundUsage = true;
					}
				}
				if (!foundUsage) {
					LOGGER.debug("certificate: {}, not for {}!", cert.getSubjectDN(), client ? "client" : "server");
					return false;
				}
			} else {
				LOGGER.debug("certificate: {}, no extkeyusage!", cert.getSubjectDN());
			}
		} catch (CertificateParsingException e) {
			LOGGER.warn("x509 certificate:", e);
		}
		return true;
	}

	/**
	 * Create certificate path from x509 certificates chain.
	 * 
	 * @param certificateChain list with chain of x509 certificates. Maybe
	 *            empty.
	 * @return generated certificate path
	 * @throws NullPointerException if provided certificateChain is {@code null}
	 */
	public static CertPath generateCertPath(List<X509Certificate> certificateChain) {
		if (certificateChain == null) {
			throw new NullPointerException("Certificate chain must not be null!");
		}
		return generateCertPath(certificateChain, certificateChain.size());
	}

	/**
	 * Create certificate path from x509 certificates chain up to the provided
	 * size.
	 * 
	 * @param certificateChain list with chain of x509 certificates. Maybe
	 *            empty.
	 * @param size size of path to be included in the certificate path.
	 * @return generated certificate path
	 * @throws NullPointerException if provided certificateChain is {@code null}
	 * @throws IllegalArgumentException if size is larger than certificate chain
	 */
	public static CertPath generateCertPath(List<X509Certificate> certificateChain, int size) {
		if (certificateChain == null) {
			throw new NullPointerException("Certificate chain must not be null!");
		}
		if (size > certificateChain.size()) {
			throw new IllegalArgumentException("size must not be larger then certificate chain!");
		}
		try {
			if (!certificateChain.isEmpty()) {
				int last = certificateChain.size() - 1;
				X500Principal issuer = null;
				for (int index = 0; index <= last; ++index) {
					X509Certificate cert = certificateChain.get(index);
					LOGGER.debug("Current Subject DN: {}", cert.getSubjectX500Principal().getName());
					if (issuer != null && !issuer.equals(cert.getSubjectX500Principal())) {
						LOGGER.debug("Actual Issuer DN: {}", cert.getSubjectX500Principal().getName());
						throw new IllegalArgumentException("Given certificates do not form a chain");
					}
					issuer = cert.getIssuerX500Principal();
					LOGGER.debug("Expected Issuer DN: {}", issuer.getName());
					if (issuer.equals(cert.getSubjectX500Principal()) && index != last) {
						// a self-signed certificate, which is not the root
						throw new IllegalArgumentException(
								"Given certificates do not form a chain, root is not the last!");
					}
				}
				if (size < certificateChain.size()) {
					List<X509Certificate> temp = new ArrayList<>();
					for (int index = 0; index < size; ++index) {
						temp.add(certificateChain.get(index));
					}
					certificateChain = temp;
				}
			}
			CertificateFactory factory = CertificateFactory.getInstance(TYPE_X509);
			return factory.generateCertPath(certificateChain);
		} catch (CertificateException e) {
			// should not happen because all Java 7 implementation MUST
			// support X.509 certificates
			throw new IllegalArgumentException("could not create X.509 certificate factory", e);
		}
	}

	/**
	 * Create validatable certificate path from x509 certificates chain.
	 * 
	 * Remove self-signed top-level root certificate and truncate certificate
	 * path at intermediate certificates from certificate authorities.
	 * 
	 * @param certificateChain list with chain of x509 certificates. May be
	 *            empty.
	 * @param certificateAuthorities list of received certificate authorities.
	 *            May be empty.
	 * @return generated certificate path
	 * @throws NullPointerException if provided certificateChain is {@code null}
	 */
	public static CertPath generateValidatableCertPath(List<X509Certificate> certificateChain,
			List<X500Principal> certificateAuthorities) {
		if (certificateChain == null) {
			throw new NullPointerException("Certificate chain must not be null!");
		}
		int size = certificateChain.size();
		if (size > 0) {
			int truncate = size;
			if (certificateAuthorities != null && !certificateAuthorities.isEmpty()) {
				truncate = 0;
				for (int index = 0; index < size; ++index) {
					X509Certificate certificate = certificateChain.get(index);
					if (certificateAuthorities.contains(certificate.getIssuerX500Principal())) {
						truncate = index + 1;
						break;
					}
				}
			}
			if (size > 1 && truncate == size) {
				int last = size - 1;
				X509Certificate cert = certificateChain.get(last);
				if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
					// a self-signed top-level root certificate
					// => reduce size to remove it
					truncate = last;
				}
			}
			size = truncate;
		}
		return generateCertPath(certificateChain, size);
	}

	/**
	 * Validate certificate path.
	 * 
	 * Use provided trusted certificates as trust anchor. Optionally truncate
	 * provided certificate path to intermediate authority certificate.
	 * 
	 * @param truncateCertificatePath truncate certificate path at trusted
	 *            certificate
	 * @param certPath certificate path
	 * @param trustedCertificates trust certificates. {@code null}, no trusts,
	 *            empty for trust all.
	 * @return certificate path actually used certificate path for validation
	 * @throws GeneralSecurityException if verification fails
	 * @deprecated use {@link #validateCertificatePathWithIssuer(boolean, CertPath, X509Certificate[])} instead.
	 */
	public static CertPath validateCertificatePath(boolean truncateCertificatePath, CertPath certPath,
			X509Certificate[] trustedCertificates) throws GeneralSecurityException {
		CertPath result = validateCertificatePathWithIssuer(truncateCertificatePath, certPath, trustedCertificates);
		if (trustedCertificates.length == 0) {
			return certPath;
		} else if (truncateCertificatePath) {
			List<? extends Certificate> list = result.getCertificates();
			int size = list.size();
			if (size > 1) {
				List<X509Certificate> chain = toX509CertificatesList(list);
				return generateCertPath(chain, size - 1);
			} else {
				return result;
			}
		} else {
			return certPath;
		}
	}

	/**
	 * Validate certificate path with issuer.
	 * 
	 * Use provided trusted certificates as trust anchor. Optionally truncate
	 * the provided certificate path to intermediate authority certificate. Add
	 * authority certificate as last certificate in the path.
	 * 
	 * The certificate path is validate using a "PKIX" {@link CertPathValidator}
	 * with the selected trusted certificate and disabled CRL. For other
	 * required setups, please implement a custom Scandium
	 * NewAdvancedCertificateVerifier.
	 * 
	 * @param truncateCertificatePath truncate certificate path at trusted
	 *            certificate
	 * @param certPath certificate path
	 * @param trustedCertificates trust certificates. {@code null}, no trusts,
	 *            empty for trust all.
	 * @return certificate path actually used certificate path for validation
	 *         with the authority certificate as last certificate
	 * @throws GeneralSecurityException if verification fails
	 * @since 2.5
	 */
	public static CertPath validateCertificatePathWithIssuer(boolean truncateCertificatePath, CertPath certPath,
			X509Certificate[] trustedCertificates) throws GeneralSecurityException {
		if (trustedCertificates == null) {
			// trust none
			throw new CertPathValidatorException("certificates are not trusted!");
		}
		List<? extends Certificate> list = certPath.getCertificates();
		if (list.isEmpty()) {
			// no certificate returned
			return certPath;
		}
		List<X509Certificate> chain = toX509CertificatesList(list);
		final int size = chain.size();
		int last = size - 1;
		// root of certificate path
		final X509Certificate root = (X509Certificate) list.get(last);
		X509Certificate trust = null;
		boolean add = false;
		boolean truncated = false;
		String mode;
		if (trustedCertificates.length == 0) {
			// trust all
			if (last == 0) {
				if (!root.getIssuerX500Principal().equals(root.getSubjectX500Principal())) {
					// single certificate, not self signed, but "trust all" ;-(.
					LOGGER.debug("   trust all- single certificate {}", root.getSubjectX500Principal());
					return certPath;
				}
				++last;
			}
			// verify certificate chain using the
			// last certificate as trust anchor
			mode = "last";
			trust = root;
		} else if (truncateCertificatePath) {
			mode = "anchor";
			for (int index = 1; index < size; ++index) {
				X509Certificate certificate = chain.get(index);
				if (contains(certificate, trustedCertificates)) {
					// verify certificate chain using a trusted
					// intermediate certificate as trust anchor
					trust = certificate;
					if (last > index) {
						last = index;
						truncated = true;
						add = true;
					}
					break;
				}
			}
			if (trust == null) {
				last = size;
				trust = searchIssuer(root, trustedCertificates);
				if (trust != null) {
					add = !root.equals(trust);
				}
			}
			if (trust == null) {
				// check, if node's certificate itself is trusted.
				X509Certificate node = chain.get(0);
				if (contains(node, trustedCertificates)) {
					if (size > 1) {
						// replace provided trust by issuer
						mode = "node's issuer";
						last = 1;
						truncated = true;
						trust = chain.get(last);
					} else {
						// single certificate, not self signed,
						// but directly trusted ;-(.
						LOGGER.debug("   trust node - single certificate {}", node.getSubjectX500Principal());
						return certPath;
					}
				}
			}
		} else {
			trust = searchIssuer(root, trustedCertificates);
			if (trust == null && contains(root, trustedCertificates)) {
				mode = "last's subject";
				trust = root;
			} else {
				mode = "last's issuer";
				add = !root.equals(trust);
			}
			last = size;
		}
		CertPath verifyCertPath = generateCertPath(chain, last);
		Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
		if (trust == null) {
			// prepare to fail :-)
			trust = trustedCertificates[0];
		}
		trustAnchors.add(new TrustAnchor(trust, null));
		if (LOGGER.isDebugEnabled()) {
			List<X509Certificate> validateChain = toX509CertificatesList(verifyCertPath.getCertificates());
			LOGGER.debug("verify: certificate path {} (orig. {})", last, size);
			X509Certificate top = null;
			for (X509Certificate certificate : validateChain) {
				LOGGER.debug("   cert : {}", certificate.getSubjectX500Principal());
				top = certificate;
			}
			if (top != null) {
				LOGGER.debug("   sign : {}", top.getIssuerX500Principal());
			}
			for (TrustAnchor anchor : trustAnchors) {
				LOGGER.debug("   trust: {}, {}", mode, anchor.getTrustedCert().getSubjectX500Principal());
			}
		}
		String algorithm = CertPathValidator.getDefaultType();
		CertPathValidator validator = CertPathValidator.getInstance(algorithm);
		PKIXParameters params = new PKIXParameters(trustAnchors);
		// TODO: implement alternative means of revocation checking
		params.setRevocationEnabled(false);
		validator.validate(verifyCertPath, params);
		if (truncated || add) {
			if (add) {
				if (!truncated) {
					chain.add(trust);
				}
				verifyCertPath = generateCertPath(chain, last + 1);
			}
			return verifyCertPath;
		} else {
			return certPath;
		}
	}

	/**
	 * Creates a modifiable x509 certificates list from provided certificates
	 * list.
	 * 
	 * @param certificates certificates list
	 * @return created modifiable x509 certificates list
	 * @throws NullPointerException if the certificate list is {@code null}.
	 * @throws IllegalArgumentException if a certificate is provided, which is
	 *             no x509 certificate.
	 */
	public static List<X509Certificate> toX509CertificatesList(List<? extends Certificate> certificates) {
		if (certificates == null) {
			throw new NullPointerException("Certificates list must not be null!");
		}
		List<X509Certificate> chain = new ArrayList<>(certificates.size());
		for (Certificate cert : certificates) {
			if (!(cert instanceof X509Certificate)) {
				throw new IllegalArgumentException("Given certificate is not X.509! " + cert);
			}
			chain.add((X509Certificate) cert);
		}
		return chain;
	}

	/**
	 * Create list of subjects from certificates.
	 * 
	 * Since 2.5 duplicates are filtered out.
	 * 
	 * @param certificates list of certificates. Maybe {@code null}.
	 * @return list of subjects of provided certificates. May be empty, if
	 *         provided list was empty or {@code null}.
	 */
	public static List<X500Principal> toSubjects(List<X509Certificate> certificates) {
		if (certificates != null && !certificates.isEmpty()) {
			List<X500Principal> subjects = new ArrayList<X500Principal>(certificates.size());
			for (X509Certificate certificate : certificates) {
				X500Principal subject = certificate.getSubjectX500Principal();
				if (!subjects.contains(subject)) {
					subjects.add(subject);
				}
			}
			return subjects;
		} else {
			return Collections.emptyList();
		}
	}

	/**
	 * Search issuer certificate by subject.
	 * 
	 * If more than one trusted certificates with that subject are available,
	 * then check, if one of them is valid and signed the provided certificate.
	 * If such a valid issuer is found, return that. Otherwise return any
	 * certificate with that subject. The final check is then left to PKIX
	 * {@link CertPathValidator}.
	 * 
	 * @param subject subject to search
	 * @param certificates to search
	 * @return certificate with provided subject, or {@code null}, if no one was
	 *         found. It's only granted, that the returned certificate has that
	 *         subject. The final check is left to PKIX
	 *         {@link CertPathValidator}.
	 * @since 2.5
	 */
	private static X509Certificate searchIssuer(X509Certificate certificate, X509Certificate[] certificates) {
		X500Principal subject = certificate.getIssuerX500Principal();
		X509Certificate anchor = null;
		for (int index = 0; index < certificates.length; ++index) {
			X509Certificate trust = certificates[index];
			if (trust != null && subject.equals(trust.getSubjectX500Principal())) {
				if (anchor != null && verifySignature(certificate, anchor)) {
					// verified anchor
					return anchor;
				} else {
					anchor = trust;
				}
			}
		}
		return anchor;
	}

	/**
	 * Verify validity and signature of certificate by CA certificate.
	 * 
	 * @param certificate signed certificate
	 * @param caCertificate signing certificate
	 * @return {@code true}, if valid, {@code false}, otherwise.
	 * @since 2.5
	 */
	private static boolean verifySignature(X509Certificate certificate, X509Certificate caCertificate) {
		try {
			caCertificate.checkValidity();
			certificate.verify(caCertificate.getPublicKey());
			return true;
		} catch (GeneralSecurityException e) {
			return false;
		}
	}

	/**
	 * Search certificate in trusts.
	 * 
	 * @param certificate certificate to search
	 * @param certificates to search
	 * @return {@code true}, if certificate is contained, {@code false},
	 *         otherwise.
	 * @throws CertificateEncodingException if encoding a certificate failed!
	 * @since 2.5
	 */
	private static boolean contains(X509Certificate certificate, X509Certificate[] certificates)
			throws CertificateEncodingException {
		for (X509Certificate trust : certificates) {
			if (certificate.equals(trust)) {
				return true;
			}
		}
		return false;
	}
}
