package org.eclipse.californium.core.coap;

import org.eclipse.californium.core.coap.CoAP.SignalingCode;
import org.eclipse.californium.elements.util.StringUtil;

public class SignalingOption extends Option{
	
	private SignalingCode code; 
	
	public SignalingOption(SignalingCode code, int optionNumber) {
		super(optionNumber);
		this.code = code;
	}

	public SignalingOption(SignalingCode code, int optionNumber,  String str) {
		super(optionNumber);
		this.code = code;
	}

	public SignalingOption(SignalingCode code, int optionNumber,  int val) {
		super(optionNumber);
		this.code = code;
	}

	public String getName() {
		return SignalingOptionNumberRegistry.toString(code,getNumber());
	}

	public SignalingCode getCode() {
		return code;
	}
	
	protected void assertValueLength() {
		SignalingOptionNumberRegistry.assertValueLength(code,getNumber(), getValue().length);
	}
	
	/**
	 * Renders the option value as string. Takes into account of option type,
	 * thus giving more accurate representation of an option {@code value}.
	 * Formats {@code value} as integer or string if so defined in
	 * {@link OptionNumberRegistry}. In case of option {@code value} is just
	 * an opaque byte array, formats this value as hex string.
	 *
	 * @return the option value as string
	 */
	public String toValueString() {
		if (value == null) {
			return "not available";
		}
		switch (SignalingOptionNumberRegistry.getFormatByNr(code,getNumber())) {
		case INTEGER:
				return Long.toString(getLongValue());
		case STRING:
			return "\"" + this.getStringValue() + "\"";
		case EMPTY:
			return "";
		default:
			return "0x" + StringUtil.byteArray2Hex(getValue());
		}
	}
}
