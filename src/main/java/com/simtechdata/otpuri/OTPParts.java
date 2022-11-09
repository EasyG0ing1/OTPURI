package com.simtechdata.otpuri;

enum OTPParts {
	LABEL_ISSUER,
	LABEL_ACCOUNT,
	PARAM_PERIOD,
	PARAM_DIGITS,
	PARAM_ALGORITHM,
	PARAM_ISSUER,
	PARAM_SECRET;

	public int index() {
		if (this.equals(OTPParts.LABEL_ISSUER)) {return 0;}
		if (this.equals(OTPParts.LABEL_ACCOUNT)) {return 1;}
		return -1;
	}

	public String get(OTPParts this) {
		return switch (this) {
			case LABEL_ISSUER -> "LABEL_ISSUER";
			case LABEL_ACCOUNT -> "LABEL_ACCOUNT";
			case PARAM_PERIOD -> "PARAM_PERIOD";
			case PARAM_DIGITS -> "PARAM_DIGITS";
			case PARAM_ALGORITHM -> "PARAM_ALGORITHM";
			case PARAM_ISSUER -> "PARAM_ISSUER";
			case PARAM_SECRET -> "PARAM_SECRET";
		};
	}

	public static OTPParts getOTPParts(String otpPart) {
		return switch (otpPart) {
			case "LABEL_ISSUER" -> LABEL_ISSUER;
			case "LABEL_ACCOUNT" -> LABEL_ACCOUNT;
			case "PARAM_PERIOD" -> PARAM_PERIOD;
			case "PARAM_DIGITS" -> PARAM_DIGITS;
			case "PARAM_ALGORITHM" -> PARAM_ALGORITHM;
			case "PARAM_ISSUER" -> PARAM_ISSUER;
			case "PARAM_SECRET" -> PARAM_SECRET;
			default -> null;
		};
	}
}
