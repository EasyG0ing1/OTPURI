package com.simtechdata.otpuri;

enum OTPParts {
	ISSUER_LABEL,
	ACCOUNT_NAME,
	PERIOD,
	DIGITS,
	ALGORITHM,
	ISSUER,
	SECRET;

	public int index() {
		if (this.equals(OTPParts.ISSUER_LABEL))
			return 0;
		if (this.equals(OTPParts.ACCOUNT_NAME))
			return 1;
		return -1;
	}

	public String get(OTPParts this) {
		return switch(this) {
			case ISSUER_LABEL -> "ISSUER_LABEL";
			case ACCOUNT_NAME -> "ACCOUNT_NAME";
			case PERIOD -> "PERIOD";
			case DIGITS -> "DIGITS";
			case ALGORITHM -> "ALGORITHM";
			case ISSUER -> "ISSUER";
			case SECRET -> "SECRET";
		};
	}

	public static OTPParts getOTPParts(String otpPart) {
		return switch(otpPart) {
			case "ISSUER_LABEL" -> ISSUER_LABEL;
			case "ACCOUNT_NAME" -> ACCOUNT_NAME;
			case "PERIOD" -> PERIOD;
			case "DIGITS" -> DIGITS;
			case "ALGORITHM" -> ALGORITHM;
			case "ISSUER" -> ISSUER;
			case "SECRET" -> SECRET;
			default -> null;
		};
	}
}
