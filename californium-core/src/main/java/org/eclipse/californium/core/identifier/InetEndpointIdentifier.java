package org.eclipse.californium.core.identifier;

import java.net.InetSocketAddress;

public class InetEndpointIdentifier implements EndpointIdentifier {

	private InetSocketAddress address;

	public InetEndpointIdentifier(InetSocketAddress address) {
		this.address = address;
	}

	public InetSocketAddress getAddress() {
		return address;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((address == null) ? 0 : address.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		InetEndpointIdentifier other = (InetEndpointIdentifier) obj;
		if (address == null) {
			if (other.address != null)
				return false;
		} else if (!address.equals(other.address))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return address.toString();
	}
}
