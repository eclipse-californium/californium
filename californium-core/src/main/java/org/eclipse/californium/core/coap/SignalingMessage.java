package org.eclipse.californium.core.coap;

import org.eclipse.californium.core.coap.CoAP.SignalingCode;

public class SignalingMessage extends Message {

	private SignalingCode code;

	public SignalingMessage(SignalingCode code) {
		if (!CoAP.isSignalingMessage(code.value)) {
			throw new IllegalArgumentException(String.format("%s is not a valid Signaling Message Code", code));
		}
		this.code = code;
		setToken(new byte[0]);
	}

	public SignalingCode getCode() {
		return code;
	}
	
	@Override
	public int getRawCode() {
		return code == null ? 0 : code.value;
	}

	@Override
	public void assertPayloadMatchsBlocksize() {
		BlockOption block1 = this.getOptions().getBlock1();
		BlockOption block2 = this.getOptions().getBlock2();
		if (block1 != null || block2 != null) {
			throw new IllegalStateException(
					"NOT implemented : Signaling Message Payload is diagnstic string and"
					+ " should not need block transfert. Payload size: "+ this.getPayloadSize());
		}
	}

	@Override
	public boolean hasBlock(final BlockOption block) {
		return false;
	}
	
	@Override
	public String toString() {
		return toTracingString(code.toString());
	}
	
	protected String toTracingString(String code) {
		String status = getStatusTracingString();
		OffloadMode offload;
		OptionSet options;
		String payload = getPayloadTracingString();
		synchronized (acknowledged) {
			offload = this.getOffloadMode();
			options = this.getOptions();
		}
		if (offload == OffloadMode.FULL) {
			return String.format("%s %s(offloaded!)",code, status);
		} else if (offload == OffloadMode.PAYLOAD) {
			return String.format("%s OptionSet=%s, %s(offloaded!)", code, options, status);
		} else {
			return String.format("%s, OptionSet=%s, %s%s", code, options, status, payload);
		}
	}
}
