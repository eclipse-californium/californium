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

import java.io.IOException;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.cloud.util.DeviceParser.Device;
import org.eclipse.californium.cloud.util.ResultConsumer.ResultCode;
import org.eclipse.californium.elements.auth.AdditionalInfo;
import org.eclipse.californium.elements.auth.ApplicationPrincipal;
import org.eclipse.californium.elements.auth.ExtensiblePrincipal;
import org.eclipse.californium.elements.util.CertPathUtil;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.elements.util.SystemResourceMonitors.SystemResourceMonitor;
import org.eclipse.californium.scandium.auth.ApplicationLevelInfoSupplier;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateIdentityResult;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.CertificateVerificationResult;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.CertificateKeyAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.dtls.x509.CertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Device credentials store.
 * 
 * @since 3.12
 */
public class DeviceManager implements DeviceGredentialsProvider, DeviceProvisioningConsumer, PrincipalInfoProvider {

	private static final Logger LOGGER = LoggerFactory.getLogger(DeviceManager.class);

	/**
	 * Resource store of device credentials.
	 */
	private final ResourceStore<DeviceParser> devices;
	/**
	 * Server's credentials for DTLS 1.2 certificate based authentication.
	 * 
	 * @since 4.0
	 */
	protected final Credentials credentials;
	/**
	 * Timeout for add credentials for auto-provisioning. Value in milliseconds.
	 * 
	 * @since 4.0
	 */
	protected final long addTimeoutMillis;
	/**
	 * Store for PreSharedKey credentials.
	 */
	protected PskStore pskStore;
	/**
	 * Certificate verifier for device certificates.
	 */
	protected CertificateVerifier certificateVerifier;
	/**
	 * Certificate provider for DTLS 1.2 server authentication.
	 */
	protected CertificateProvider certificateProvider;
	/**
	 * Application level info supplier.
	 * <p>
	 * Adds application level device info to principal.
	 */
	protected ApplicationLevelInfoSupplier infoSupplier;

	/**
	 * Creates device manager.
	 * 
	 * @param devices device store with PreSharedKey, RawPublicKey and x509
	 *            credentials. May be {@code null}.
	 * @param credentials server's credentials for DTLS 1.2 certificate based
	 *            authentication. May be {@code null}.
	 * @param addTimeoutMillis timeout in milliseconds configuration values
	 * @since 4.0 (added parameter addTimeoutMillis)
	 */
	public DeviceManager(ResourceStore<DeviceParser> devices, Credentials credentials, long addTimeoutMillis) {
		this.devices = devices;
		if (credentials != null && credentials.getPrivateKey() != null && credentials.getPublicKey() != null) {
			this.credentials = credentials;
		} else {
			this.credentials = null;
		}
		this.addTimeoutMillis = addTimeoutMillis;
	}

	/**
	 * Create application level info supplier.
	 * 
	 * @return application level info supplier
	 */
	protected ApplicationLevelInfoSupplier createInfoSupplier() {
		return new ApplicationLevelInfoSupplier() {

			@Override
			public AdditionalInfo getInfo(Principal clientIdentity, Object customArgument) {
				if (customArgument instanceof AdditionalInfo) {
					return (AdditionalInfo) customArgument;
				}
				return createAdditionalInfo(clientIdentity);
			}
		};
	}

	@Override
	public void add(PrincipalInfo info, long time, String data, final ResultConsumer response) {
		add(devices, info, time, data, response);
	}

	protected void add(final ResourceStore<DeviceParser> devices, PrincipalInfo info, long time, String data,
			final ResultConsumer response) {
		if (devices == null) {
			response.results(ResultCode.SERVER_ERROR, "no credentials available.");
			return;
		}
		SystemResourceMonitor monitor = devices.getMonitor();
		if (!(monitor instanceof ResourceChangedHandler)) {
			response.results(ResultCode.SERVER_ERROR, "no ResourceChangedHandler.");
			return;
		}
		final Semaphore semaphore = devices.getSemaphore();
		try {
			if (semaphore.tryAcquire(addTimeoutMillis, TimeUnit.MILLISECONDS)) {
				boolean release = true;
				try (StringReader reader = new StringReader(data)) {
					int result = devices.getResource().load(reader);
					if (result > 0) {
						((ResourceChangedHandler) monitor).changed(new ResultConsumer() {

							@Override
							public void results(ResultCode code, String message) {
								try {
									response.results(code, message);
								} finally {
									semaphore.release();
								}
							}
						});
						release = false;
					} else {
						LOGGER.info("no credentials added!");
						response.results(ResultCode.PROVISIONING_ERROR, "no credentials added.");
					}
				} catch (IllegalArgumentException e) {
					response.results(ResultCode.PROVISIONING_ERROR, e.getMessage());
				} catch (IOException e) {
					response.results(ResultCode.SERVER_ERROR, "failed to read new credentials. " + e.getMessage());
				} finally {
					if (release) {
						semaphore.release();
					}
				}
			} else {
				response.results(ResultCode.TOO_MANY_REQUESTS, "Too busy.");
			}
		} catch (InterruptedException e) {
			response.results(ResultCode.SERVER_ERROR, "Shutdown.");
		}
	}

	@Override
	public PskStore getPskStore() {
		if (devices == null) {
			return null;
		}
		if (pskStore == null) {
			pskStore = new DevicePskStore();
		}
		return pskStore;
	}

	@Override
	public CertificateVerifier getCertificateVerifier() {
		if (devices == null || credentials == null) {
			return null;
		}
		if (certificateVerifier == null) {
			certificateVerifier = new DeviceCertificateVerifier(
					createCertificateTypesList(credentials.hasCertificateChain()));
		}
		return certificateVerifier;
	}

	@Override
	public CertificateProvider getCertificateProvider() {
		if (devices == null || credentials == null) {
			return null;
		}
		if (certificateProvider == null) {
			certificateProvider = new ServerCertificateProvider(
					createCertificateTypesList(credentials.hasCertificateChain()));
		}
		return certificateProvider;
	}

	@Override
	public ApplicationLevelInfoSupplier getInfoSupplier() {
		if (infoSupplier == null) {
			infoSupplier = new ApplicationLevelInfoSupplier() {

				@Override
				public AdditionalInfo getInfo(Principal clientIdentity, Object customArgument) {
					if (customArgument instanceof AdditionalInfo) {
						return (AdditionalInfo) customArgument;
					}
					return createAdditionalInfo(clientIdentity);
				}
			};
		}
		return infoSupplier;
	}

	/**
	 * Create additional info for a device.
	 * 
	 * @param clientIdentity principal for the device
	 * @return additional info of device, or {@code null}, if not available.
	 */
	public AdditionalInfo createAdditionalInfo(Principal clientIdentity) {
		if (devices == null) {
			return null;
		}
		if (ApplicationPrincipal.ANONYMOUS.equals(clientIdentity)) {
			return ApplicationAnonymous.APPL_AUTH_PRINCIPAL.getExtendedInfo();
		}
		return createAdditionalInfo(devices.getResource().getByPrincipal(clientIdentity));
	}

	/**
	 * Create additional info for a device.
	 * 
	 * @param device device to create additional info
	 * @return additional info of device, or {@code null}, if provided device is
	 *         {@code null}. For banned devices {@link AdditionalInfo#empty()}
	 *         is returned.
	 */
	public AdditionalInfo createAdditionalInfo(Device device) {
		if (device != null) {
			if (device.ban) {
				return AdditionalInfo.empty();
			} else {
				Map<String, Object> info = new HashMap<>();
				info.put(PrincipalInfo.INFO_NAME, device.name);
				info.put(PrincipalInfo.INFO_PROVIDER, this);
				return AdditionalInfo.from(info);
			}
		}
		return null;
	}

	@Override
	public PrincipalInfo getPrincipalInfo(Principal principal) {
		if (principal instanceof ExtensiblePrincipal) {
			@SuppressWarnings("unchecked")
			ExtensiblePrincipal<? extends Principal> extensiblePrincipal = (ExtensiblePrincipal<? extends Principal>) principal;
			Device device = null;
			if (extensiblePrincipal.getExtendedInfo().isEmpty()) {
				device = devices.getResource().getByPrincipal(principal);
			} else {
				String name = extensiblePrincipal.getExtendedInfo().get(PrincipalInfo.INFO_NAME, String.class);
				DeviceManager manager = extensiblePrincipal.getExtendedInfo().get(PrincipalInfo.INFO_PROVIDER,
						DeviceManager.class);
				if (manager == this && name != null && !name.contains("/")) {
					device = devices.getResource().get(name);
				}
			}
			if (device != null && !device.ban) {
				return new PrincipalInfo(device.group, device.name, device.type);
			}
		}
		return null;
	}

	public List<CertificateType> createCertificateTypesList(boolean x509) {
		List<CertificateType> types = new ArrayList<>(2);
		types.add(CertificateType.RAW_PUBLIC_KEY);
		if (x509) {
			types.add(CertificateType.X_509);
		}
		return types;
	}

	private class DevicePskStore implements PskStore {

		private final PskPublicInformation dummy = new PskPublicInformation("dummy");

		@Override
		public boolean hasEcdhePskSupported() {
			return true;
		}

		@Override
		public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverName,
				PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed,
				boolean useExtendedMasterSecret) {
			Device device = devices.getResource().getByPreSharedKeyIdentity(identity.getPublicInfoAsString());
			AdditionalInfo additionalInfo = createAdditionalInfo(device);
			if (additionalInfo != null && !additionalInfo.isEmpty()) {
				return new PskSecretResult(cid, identity, SecretUtil.create(device.pskSecret, "PSK"), additionalInfo);
			} else {
				return new PskSecretResult(cid, identity, null);
			}
		}

		@Override
		public PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
			return dummy;
		}

		@Override
		public void setResultHandler(HandshakeResultHandler resultHandler) {
		}
	};

	/**
	 * Certificate verifier.
	 * <p>
	 * Verifies that a provided Raw Public Key certificate is contained in the
	 * device credentials.
	 */
	protected class DeviceCertificateVerifier implements CertificateVerifier {

		private final List<CertificateType> supportedCertificateTypes;

		protected DeviceCertificateVerifier(List<CertificateType> supportedCertificateTypes) {
			this.supportedCertificateTypes = Collections.unmodifiableList(supportedCertificateTypes);
		}

		@Override
		public List<CertificateType> getSupportedCertificateTypes() {
			return supportedCertificateTypes;
		}

		@Override
		public CertificateVerificationResult verifyCertificate(ConnectionId cid, ServerNames serverName,
				InetSocketAddress remotePeer, boolean clientUsage, boolean verifySubject,
				boolean truncateCertificatePath, CertificateMessage message) {
			CertPath certChain = message.getCertificateChain();
			if (certChain == null) {
				PublicKey publicKey = message.getPublicKey();
				AdditionalInfo info = getByRawPublicKey(publicKey);
				if (info == null) {
					LOGGER.info("Certificate validation failed: Raw public key is not trusted");
					AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
					return new CertificateVerificationResult(cid,
							new HandshakeException("Raw public key is not trusted!", alert));
				} else if (info.isEmpty()) {
					LOGGER.info("Certificate validation failed: Raw public key is banned");
					AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
					return new CertificateVerificationResult(cid,
							new HandshakeException("Raw public key is banned!", alert));
				} else {
					return new CertificateVerificationResult(cid, publicKey, info);
				}
			}
			try {
				if (!message.isEmpty()) {
					List<? extends Certificate> path = certChain.getCertificates();
					Certificate certificate = path.get(0);
					if (certificate instanceof X509Certificate) {
						X509Certificate deviceCertificate = (X509Certificate) certificate;
						if (!CertPathUtil.canBeUsedForAuthentication(deviceCertificate, clientUsage)) {
							LOGGER.debug("Certificate validation failed: key usage doesn't match");
							AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
							return new CertificateVerificationResult(cid,
									new HandshakeException("Key Usage doesn't match!", alert));
						}
						X509Certificate[] trustedCertificates = getTrustedCertificates();
						if (trustedCertificates == null || trustedCertificates.length == 0) {
							LOGGER.info("Certificate validation failed: no trusted CA");
							trustedCertificates = null;
						} else {
							LOGGER.debug("{} CA x509 certificates.", trustedCertificates.length);
						}
						certChain = CertPathUtil.validateCertificatePathWithIssuer(truncateCertificatePath, certChain,
								trustedCertificates);
						String role = "";
						AdditionalInfo info = getByX509(deviceCertificate);
						if (info == null || !info.isEmpty()) {
							// check CA
							path = certChain.getCertificates();
							if (path.size() > 1) {
								certificate = path.get(path.size() - 1);
								if (certificate instanceof X509Certificate) {
									AdditionalInfo caInfo = getByX509((X509Certificate) certificate);
									if (caInfo != null && (info == null || caInfo.isEmpty())) {
										role = "CA ";
										info = caInfo;
									}
								}
							}
						}
						if (info == null) {
							LOGGER.info("Certificate validation failed: x509 certificate is not trusted");
							AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
							return new CertificateVerificationResult(cid,
									new HandshakeException("x509 certificate is not trusted!", alert));
						} else if (info.isEmpty()) {
							LOGGER.info("{}Certificate validation failed: x509 certificate is banned", role);
							AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
							return new CertificateVerificationResult(cid,
									new HandshakeException(role + "x509 certificate is banned!", alert));
						} else {
							return new CertificateVerificationResult(cid, certChain, info);
						}
					}
				}
				return new CertificateVerificationResult(cid, certChain, null);
			} catch (

			CertPathValidatorException e) {
				Throwable cause = e.getCause();
				if (cause instanceof CertificateExpiredException) {
					LOGGER.debug("Certificate expired: {}", cause.getMessage());
					AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.CERTIFICATE_EXPIRED);
					return new CertificateVerificationResult(cid, new HandshakeException("Certificate expired", alert));
				} else if (cause != null) {
					LOGGER.debug("Certificate validation failed: {}/{}", e.getMessage(), cause.getMessage());
				} else {
					LOGGER.debug("Certificate validation failed: {}", e.getMessage());
				}
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
				return new CertificateVerificationResult(cid,
						new HandshakeException("Certificate chain could not be validated", alert, e));
			} catch (GeneralSecurityException e) {
				if (LOGGER.isTraceEnabled()) {
					LOGGER.trace("Certificate validation failed", e);
				} else if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Certificate validation failed due to {}", e.getMessage());
				}
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR);
				return new CertificateVerificationResult(cid,
						new HandshakeException("Certificate chain could not be validated", alert, e));
			}
		}

		@Override
		public List<X500Principal> getAcceptedIssuers() {
			return Collections.emptyList();
		}

		@Override
		public void setResultHandler(HandshakeResultHandler resultHandler) {
		}

		protected AdditionalInfo getByRawPublicKey(PublicKey publicKey) {
			Device device = devices.getResource().getByRawPublicKey(publicKey);
			return createAdditionalInfo(device);
		}

		protected AdditionalInfo getByX509(X509Certificate certificate) {
			Device device = devices.getResource().getByX509(certificate);
			if (LOGGER.isDebugEnabled()) {
				String cn = CertPathUtil.getSubjectsCn(certificate);
				LOGGER.debug("{}x509 certificate for {}", device == null ? "No " : "", cn);
			}
			return createAdditionalInfo(device);
		}

		protected X509Certificate[] getTrustedCertificates() {
			return devices.getResource().getTrustedCertificates();
		}
	}

	/**
	 * Server certificate provider.
	 */
	protected class ServerCertificateProvider implements CertificateProvider {

		private List<CertificateType> supportedCertificateTypes;

		private List<CertificateKeyAlgorithm> supportedCertificateKeyAlgorithms = Collections
				.unmodifiableList(Arrays.asList(CertificateKeyAlgorithm.getAlgorithm(credentials.getPublicKey())));

		public ServerCertificateProvider(List<CertificateType> supportedCertificateTypes) {
			this.supportedCertificateTypes = Collections.unmodifiableList(supportedCertificateTypes);
		}

		@Override
		public List<CertificateKeyAlgorithm> getSupportedCertificateKeyAlgorithms() {
			return supportedCertificateKeyAlgorithms;
		}

		@Override
		public List<CertificateType> getSupportedCertificateTypes() {
			return supportedCertificateTypes;
		}

		@Override
		public CertificateIdentityResult requestCertificateIdentity(ConnectionId cid, boolean client,
				List<X500Principal> issuers, ServerNames serverNames,
				List<CertificateKeyAlgorithm> certificateKeyAlgorithms,
				List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms, List<SupportedGroup> curves) {
			if (credentials.hasCertificateChain()) {
				return new CertificateIdentityResult(cid, credentials.getPrivateKey(),
						credentials.getCertificateChainAsList());
			} else {
				return new CertificateIdentityResult(cid, credentials.getPrivateKey(), credentials.getPublicKey());
			}
		}

		@Override
		public void setResultHandler(HandshakeResultHandler resultHandler) {

		}

	};
}
