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
package org.eclipse.californium.cloud.s3.util;

import java.net.InetSocketAddress;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.cloud.util.DeviceManager;
import org.eclipse.californium.cloud.util.DeviceParser;
import org.eclipse.californium.cloud.util.DeviceParser.Device;
import org.eclipse.californium.cloud.util.ResourceStore;
import org.eclipse.californium.cloud.util.ResultConsumer;
import org.eclipse.californium.cloud.util.ResultConsumer.ResultCode;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.auth.AdditionalInfo;
import org.eclipse.californium.elements.auth.ExtensiblePrincipal;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.CertificateVerificationResult;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.dtls.x509.CertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Domain device manager.
 * 
 * Organize devices into separate domains.
 * 
 * @since 3.12
 */
public class DomainDeviceManager extends DeviceManager implements DeviceGroupProvider {

	private static final Logger LOGGER = LoggerFactory.getLogger(DomainDeviceManager.class);

	/**
	 * Default device domain, if domain name is not available in additional
	 * info.
	 */
	public static final String DEFAULT_DOMAIN = "default";

	/**
	 * Key for domain name in additional info.
	 */
	public static final String INFO_DOMAIN = "domain";

	/**
	 * Map of domains.
	 */
	private final ConcurrentMap<String, ResourceStore<DeviceParser>> domains;

	/**
	 * Creates device manager.
	 * 
	 * @param domains domains of device stores with PreSharedKey and
	 *            RawPublicKey credentials
	 * @param privateKey private key of DTLS 1.2 server for device communication
	 * @param publicKey public key of DTLS 1.2 server for device communication
	 */
	public DomainDeviceManager(ConcurrentMap<String, ResourceStore<DeviceParser>> domains, PrivateKey privateKey,
			PublicKey publicKey) {
		super(null, privateKey, publicKey);
		this.domains = domains;
	}

	@Override
	public void add(DeviceInfo info, long time, String data, final ResultConsumer response) {
		if (!(info instanceof DomainDeviceInfo)) {
			response.results(ResultCode.SERVER_ERROR, "no DomainDeviceInfo.");
			return;
		}
		final String domain = ((DomainDeviceInfo) info).domain;
		ResourceStore<DeviceParser> store = domains.get(domain);
		if (store == null) {
			response.results(ResultCode.SERVER_ERROR, "Domain " + domain + " not available.");
			return;
		}
		add(store, info, time, data, new ResultConsumer() {

			@Override
			public void results(ResultCode resultCode, String message) {
				response.results(resultCode, domain + ": " + message);
			}

		});
	}

	@Override
	public AdvancedPskStore getPskStore() {
		if (domains == null) {
			return null;
		}
		if (pskStore == null) {
			pskStore = new DevicePskStore();
		}
		return pskStore;
	}

	@Override
	public NewAdvancedCertificateVerifier getCertificateVerifier() {
		if (domains == null || publicKey == null || privateKey == null) {
			return null;
		}
		if (certificateVerifier == null) {
			certificateVerifier = new DeviceCertificateVerifier();
		}
		return certificateVerifier;
	}

	@Override
	public CertificateProvider getCertificateProvider() {
		if (domains == null || publicKey == null || privateKey == null) {
			return null;
		}
		if (certificateProvider == null) {
			certificateProvider = new ServerCertificateProvider();
		}
		return certificateProvider;
	}

	@Override
	public AdditionalInfo createAdditionalInfo(Principal clientIdentity) {
		if (domains == null) {
			return null;
		}
		for (Entry<String, ResourceStore<DeviceParser>> domain : domains.entrySet()) {
			Device device = domain.getValue().getResource().getByPrincipal(clientIdentity);
			if (device != null) {
				return createAdditionalInfo(domain.getKey(), device);
			}
		}
		return null;
	}

	/**
	 * Create additional info for a domain device.
	 * 
	 * @param domain domain name
	 * @param device device to create additional info
	 * @return additional info of device, or {@code null}, if provided device is
	 *         {@code null}.
	 */
	public AdditionalInfo createAdditionalInfo(String domain, Device device) {
		if (device != null) {
			Map<String, Object> info = new HashMap<>();
			info.put(INFO_NAME, device.name);
			info.put(INFO_GROUP, device.group);
			info.put(INFO_DOMAIN, domain);
			if (device.provisioning) {
				info.put(INFO_PROVISIONING, "1");
			}
			return AdditionalInfo.from(info);
		}
		return null;
	}

	@Override
	public Set<String> getGroup(String domain, String group) {
		ResourceStore<DeviceParser> resource = domains != null ? domains.get(domain) : null;
		if (resource == null) {
			return Collections.emptySet();
		} else {
			return resource.getResource().getGroup(group);
		}
	}

	/**
	 * PreSharedKey store for devices in domains.
	 */
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
			DomainNamePair domainName = DomainNamePair.fromName(identity.getPublicInfoAsString());
			if (domainName.domain != null) {
				ResourceStore<DeviceParser> resource = domains.get(domainName.domain);
				if (resource != null) {
					Device device = resource.getResource().getByPreSharedKeyIdentity(domainName.name);
					if (device != null) {
						AdditionalInfo info = createAdditionalInfo(domainName.domain, device);
						return new PskSecretResult(cid, identity, SecretUtil.create(device.pskSecret, "PSK"), info);
					}
				}
			} else {
				Device device = null;
				String domain = null;
				for (Entry<String, ResourceStore<DeviceParser>> domainEntry : domains.entrySet()) {
					Device match = domainEntry.getValue().getResource().getByPreSharedKeyIdentity(domainName.name);
					if (match != null) {
						if (device == null) {
							device = match;
							domain = domainEntry.getKey();
						} else {
							// ambiguous
							device = null;
							break;
						}
					}
				}
				if (device != null) {
					AdditionalInfo info = createAdditionalInfo(domain, device);
					return new PskSecretResult(cid, identity, SecretUtil.create(device.pskSecret, "PSK"), info);
				}
			}
			return new PskSecretResult(cid, identity, null);
		}

		@Override
		public PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
			return dummy;
		}

		@Override
		public void setResultHandler(HandshakeResultHandler resultHandler) {
		}
	}

	/**
	 * Certificate verifier for devices in domains.
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
			for (Entry<String, ResourceStore<DeviceParser>> domain : domains.entrySet()) {
				Device device = domain.getValue().getResource().getByRawPublicKey(publicKey);
				if (device != null) {
					AdditionalInfo info = createAdditionalInfo(domain.getKey(), device);
					return new CertificateVerificationResult(cid, publicKey, info);
				}
			}
			LOGGER.warn("Certificate validation failed: Raw public key is not trusted");
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
			return new CertificateVerificationResult(cid,
					new HandshakeException("Raw public key is not trusted!", alert), null);
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
	 * Get device info.
	 * 
	 * Get device info from additional info of the principal.
	 * 
	 * @param principal the principal of the device
	 * @return device info, or {@code null}, if not available.
	 * @see EndpointContext#getPeerIdentity()
	 */
	public static DomainDeviceInfo getDeviceInfo(Principal principal) {
		if (principal instanceof ExtensiblePrincipal) {
			@SuppressWarnings("unchecked")
			ExtensiblePrincipal<? extends Principal> extensiblePrincipal = (ExtensiblePrincipal<? extends Principal>) principal;
			String name = extensiblePrincipal.getExtendedInfo().get(DeviceManager.INFO_NAME, String.class);
			if (name != null && !name.contains("/")) {
				String group = extensiblePrincipal.getExtendedInfo().get(DeviceManager.INFO_GROUP, String.class);
				String domain = extensiblePrincipal.getExtendedInfo().get(INFO_DOMAIN, String.class);
				String prov = extensiblePrincipal.getExtendedInfo().get(DeviceManager.INFO_PROVISIONING, String.class);
				return new DomainDeviceInfo(domain, group, name, prov);
			}
		}
		return null;
	}

	/**
	 * Domain device info.
	 */
	public static class DomainDeviceInfo extends DeviceInfo {

		/**
		 * Device domain.
		 */
		public final String domain;

		/**
		 * Create domain device info
		 * 
		 * @param domain domain name of device
		 * @param group group of device
		 * @param name name of device
		 * @param provisioning {@code "1"}, if credentials are used for auto
		 *            provisioning, otherwise device credentials.
		 */
		protected DomainDeviceInfo(String domain, String group, String name, String provisioning) {
			super(group, name, provisioning);
			if (domain == null) {
				domain = DEFAULT_DOMAIN;
			}
			this.domain = domain;
		}

		@Override
		public String toString() {
			return name + "@" + domain + " (" + group + (provisioning ? ",prov)" : ")");
		}
	}

	static {
		setDeviceInfoProvider(new DeviceInfoProvider() {

			@Override
			public DeviceInfo getDeviceInfo(Principal principal) {
				return DomainDeviceManager.getDeviceInfo(principal);
			}
		});
	}
}
