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

import java.net.InetSocketAddress;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.cloud.util.DeviceParser.Device;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.auth.AdditionalInfo;
import org.eclipse.californium.elements.auth.ExtensiblePrincipal;
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
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.dtls.x509.CertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Device credentials store.
 * 
 * @since 3.12
 */
public class DeviceManager implements DeviceGredentialsProvider {

	private static final Logger LOGGER = LoggerFactory.getLogger(DeviceManager.class);

	/**
	 * Key for configured device name in additional info.
	 */
	public static final String INFO_NAME = "name";
	/**
	 * Key for configured device group in additional info.
	 */
	public static final String INFO_GROUP = "group";

	/**
	 * Resource store of device credentials.
	 */
	private final ResourceStore<DeviceParser> devices;
	/**
	 * Private key of DTLS 1.2 server for certificate based authentication.
	 */
	protected final PrivateKey privateKey;
	/**
	 * Public key of DTLS 1.2 server for certificate based authentication.
	 */
	protected final PublicKey publicKey;
	/**
	 * Store for PreSharedKey credentials.
	 */
	protected AdvancedPskStore pskStore;
	/**
	 * Certificate verifier for device certificates.
	 */
	protected NewAdvancedCertificateVerifier certificateVerifier;
	/**
	 * Certificate provider for DTLS 1.2 server authentication.
	 */
	protected CertificateProvider certificateProvider;
	/**
	 * Application level info supplier.
	 * 
	 * Adds application level device info to principal.
	 */
	protected ApplicationLevelInfoSupplier infoSupplier;

	/**
	 * Creates device manager.
	 * 
	 * @param devices device store with PreSharedKey and RawPublicKey
	 *            credentials
	 * @param privateKey private key of DTLS 1.2 server for device communication
	 * @param publicKey public key of DTLS 1.2 server for device communication
	 */
	public DeviceManager(ResourceStore<DeviceParser> devices, PrivateKey privateKey, PublicKey publicKey) {
		this.devices = devices;
		this.privateKey = privateKey;
		this.publicKey = publicKey;
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
	public AdvancedPskStore getPskStore() {
		if (devices == null) {
			return null;
		}
		if (pskStore == null) {
			pskStore = new DevicePskStore();
		}
		return pskStore;
	}

	@Override
	public NewAdvancedCertificateVerifier getCertificateVerifier() {
		if (devices == null || publicKey == null || privateKey == null) {
			return null;
		}
		if (certificateVerifier == null) {
			certificateVerifier = new DeviceCertificateVerifier();
		}
		return certificateVerifier;
	}

	@Override
	public CertificateProvider getCertificateProvider() {
		if (devices == null || publicKey == null || privateKey == null) {
			return null;
		}
		if (certificateProvider == null) {
			certificateProvider = new ServerCertificateProvider();
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
		return createAdditionalInfo(devices.getResource().getByPrincipal(clientIdentity));
	}

	/**
	 * Create additional info for a device.
	 * 
	 * @param device device to create additional info
	 * @return additional info of device, or {@code null}, if provided device is
	 *         {@code null}.
	 */
	public AdditionalInfo createAdditionalInfo(Device device) {
		if (device != null) {
			Map<String, Object> info = new HashMap<>();
			info.put(INFO_NAME, device.name);
			info.put(INFO_GROUP, device.group);
			return AdditionalInfo.from(info);
		}
		return null;
	}

	private class DevicePskStore implements AdvancedPskStore {

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
			if (device != null) {
				return new PskSecretResult(cid, identity, SecretUtil.create(device.pskSecret, "PSK"),
						createAdditionalInfo(device));
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
	 * 
	 * Verifies that a provided Raw Public Key certificate is contained in the
	 * device credentials.
	 */
	private class DeviceCertificateVerifier implements NewAdvancedCertificateVerifier {

		private final List<CertificateType> supportedCertificateTypes = Arrays.asList(CertificateType.RAW_PUBLIC_KEY);

		@Override
		public List<CertificateType> getSupportedCertificateTypes() {
			return supportedCertificateTypes;
		}

		@Override
		public CertificateVerificationResult verifyCertificate(ConnectionId cid, ServerNames serverName,
				InetSocketAddress remotePeer, boolean clientUsage, boolean verifySubject,
				boolean truncateCertificatePath, CertificateMessage message) {
			PublicKey publicKey = message.getPublicKey();
			Device device = devices.getResource().getByRawPublicKey(publicKey);
			if (device != null) {
				return new CertificateVerificationResult(cid, publicKey, createAdditionalInfo(device));
			} else {
				LOGGER.warn("Certificate validation failed: Raw public key is not trusted");
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
				return new CertificateVerificationResult(cid,
						new HandshakeException("Raw public key is not trusted!", alert), null);
			}
		}

		@Override
		public List<X500Principal> getAcceptedIssuers() {
			return Collections.emptyList();
		}

		@Override
		public void setResultHandler(HandshakeResultHandler resultHandler) {
		}

	}

	/**
	 * Server certificate provider.
	 */
	protected class ServerCertificateProvider implements CertificateProvider {

		private List<CertificateType> supportedCertificateTypes = Collections
				.unmodifiableList(Arrays.asList(CertificateType.RAW_PUBLIC_KEY));
		private List<CertificateKeyAlgorithm> supportedCertificateKeyAlgorithms = Collections
				.unmodifiableList(Arrays.asList(CertificateKeyAlgorithm.getAlgorithm(publicKey)));

		public ServerCertificateProvider() {

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
			return new CertificateIdentityResult(cid, privateKey, publicKey);
		}

		@Override
		public void setResultHandler(HandshakeResultHandler resultHandler) {

		}
	};

	/**
	 * Get device info.
	 * 
	 * Get device info from additional info of the principal.
	 * 
	 * @param principal the principal of the device
	 * @return device info, or {@code null}, if not available.
	 * @see EndpointContext#getPeerIdentity()
	 */
	public static DeviceInfo getDeviceInfo(Principal principal) {
		if (principal instanceof ExtensiblePrincipal) {
			@SuppressWarnings("unchecked")
			ExtensiblePrincipal<? extends Principal> extensiblePrincipal = (ExtensiblePrincipal<? extends Principal>) principal;
			String name = extensiblePrincipal.getExtendedInfo().get(DeviceManager.INFO_NAME, String.class);
			if (name != null && !name.contains("/")) {
				String group = extensiblePrincipal.getExtendedInfo().get(DeviceManager.INFO_GROUP, String.class);
				return new DeviceInfo(group, name);
			}
		}
		return null;
	}

	/**
	 * Device info.
	 */
	public static class DeviceInfo {

		/**
		 * Device name.
		 */
		public final String name;
		/**
		 * Device group.
		 */
		public final String group;

		/**
		 * Create device info
		 * 
		 * @param group group of device
		 * @param name name of device
		 */
		protected DeviceInfo(String group, String name) {
			this.name = name;
			this.group = group;
		}

		@Override
		public String toString() {
			return name + " (" + group + ")";
		}
	}
}
