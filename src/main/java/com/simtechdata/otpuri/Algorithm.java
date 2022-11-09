package com.simtechdata.otpuri;

public enum Algorithm {
	SHA1,
	SHA256,
	SHA512;

	public String get(Algorithm this) {
		return switch(this) {
		    case SHA1 ->   "SHA1";
			case SHA256 -> "SHA256";
			case SHA512 -> "SHA512";
		};
	}

	public static Algorithm getAlgorithm(String algorithm) {
		return switch(algorithm) {
			case "SHA1" ->   Algorithm.SHA1;
			case "SHA256" -> Algorithm.SHA256;
			case "SHA512" -> Algorithm.SHA512;
			default -> null;
		};
	}
}
