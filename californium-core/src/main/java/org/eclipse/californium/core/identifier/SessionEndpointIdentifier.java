package org.eclipse.californium.core.identifier;


public class SessionEndpointIdentifier implements EndpointIdentifier {

	private String sessionId;

	public SessionEndpointIdentifier(String sessionID) {
		this.sessionId = sessionID;
	}

	public String getSessionId() {
		return sessionId;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((sessionId == null) ? 0 : sessionId.hashCode());
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
		SessionEndpointIdentifier other = (SessionEndpointIdentifier) obj;
		if (sessionId == null) {
			if (other.sessionId != null)
				return false;
		} else if (!sessionId.equals(other.sessionId))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return String.format("SessionID : %s", sessionId);
	}
}
