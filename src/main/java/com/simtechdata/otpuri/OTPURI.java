package com.simtechdata.otpuri;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static com.simtechdata.otpuri.OTPParts.*;

public class OTPURI {

	private static final String    resource = "otpauth";
	private static final String    protocol = "totp";
	private final        String    labelIssuer;
	private final        String    accountName;
	private final        String    paramSecret;
	private final        String    paramIssuer;
	private final        Algorithm paramAlgorithm; //Options: SHA1, SHA256, SHA512; default = SHA1
	private final        String    paramDigits; //Number of digits to return, default = 6
	private final        String    paramPeriod; //In Seconds, default = 30

	public static class Builder {

		public Builder() {}

		public Builder(String otpAuthString) {
			Map<OTPParts, String> partsMap = getPartsMap(otpAuthString);
			if (partsMap != null) {
				for (OTPParts part : partsMap.keySet()) {
					switch (part) {
						case ISSUER_LABEL -> labelIssuer = partsMap.get(ISSUER_LABEL);
						case ACCOUNT_NAME -> accountName = partsMap.get(ACCOUNT_NAME);
						case SECRET -> paramSecret = partsMap.get(SECRET);
						case ISSUER -> paramIssuer = partsMap.get(ISSUER);
						case ALGORITHM -> paramAlgorithm = Algorithm.getAlgorithm(partsMap.get(ALGORITHM));
						case DIGITS -> paramDigits = partsMap.get(DIGITS);
						case PERIOD -> paramPeriod = partsMap.get(PERIOD);
					}
				}
			}
		}

		private Map<OTPParts, String> getPartsMap(String otpAuthString) {
			Map<OTPParts, String> map         = new HashMap<>();
			String                finalString = URLDecoder.decode(otpAuthString, StandardCharsets.ISO_8859_1);
			if (!finalString.contains(resource)) {
				return null;
			}
			String[] lines         = finalString.replaceFirst(resource + "://(hotp|totp)/", "").replaceFirst(resource + "://(hotp|totp)", "").split("\\?");
			String   first         = lines[0];
			String   last          = lines[1];
			boolean  extractIssuer = false;
			if (first.contains(":")) {
				String[] labelParts = first.split(":");
				map.put(ISSUER_LABEL, labelParts[ISSUER_LABEL.index()]);
				map.put(ACCOUNT_NAME, labelParts[ACCOUNT_NAME.index()]);
			}
			else if (first.length() > 2) {
				map.put(ACCOUNT_NAME, first);
				extractIssuer = true;
			}
			String[] otpParameterArray = last.split("&");
			for (String otpParameter : otpParameterArray) {
				String[] parameterLabelValue = otpParameter.split("=");
				String   parameterLabel      = parameterLabelValue[0].toLowerCase();
				String   parameterValue      = parameterLabelValue[1];
				switch (parameterLabel) {
					case "secret" -> map.put(SECRET, parameterValue);
					case "issuer" -> map.put(ISSUER, parameterValue);
					case "algorithm" -> map.put(ALGORITHM, parameterValue.toUpperCase());
					case "digits" -> map.put(DIGITS, parameterValue);
					case "period" -> map.put(PERIOD, parameterValue);
				}
			}
			if (extractIssuer) {
				if (map.containsKey(ISSUER)) {map.put(ISSUER_LABEL, map.get(ISSUER));}
			}
            setFromAuthString = true;
			return map;
		}

		private String    labelIssuer;
		private String    accountName;
		private String    paramSecret    = "";
		private String    paramIssuer    = "";
		private Algorithm paramAlgorithm = Algorithm.SHA1; //Options: SHA1, SHA256, SHA512; default = SHA1
		private String    paramDigits    = "6"; //Number of digits to return, default = 6
		private String    paramPeriod    = "30"; //In Seconds, default = 30
        private boolean setFromAuthString = false;

		public Builder labelIssuer(String issuer) {
			this.labelIssuer = issuer;
			return this;
		}

		public Builder paramIssuer(String issuer) {
			this.paramIssuer = issuer;
			return this;
		}

		public Builder issuer(String issuer) {
			this.labelIssuer = issuer;
			this.paramIssuer = issuer;
			return this;
		}

		public Builder accountName(String accountName) {
			this.accountName = accountName;
			return this;
		}

		public Builder secret(String secret) {
			this.paramSecret = secret;
			return this;
		}

		public Builder algorithm(Algorithm algorithm) {
			this.paramAlgorithm = algorithm;
			return this;
		}

		public Builder digits(int returnDigits) {
			if (returnDigits < 6 || returnDigits > 8) {throw new RuntimeException("digits must be one of these numbers: 6, 7, or 8");}
			this.paramDigits = String.valueOf(returnDigits);
			return this;
		}

		public Builder period(int period) {
			boolean valid = (period == 15) || (period == 30) || (period == 60);
			if (!valid) {throw new RuntimeException("period can only be 15, 30, or 60");}
			else {this.paramPeriod = String.valueOf(period);}
			return this;
		}

		public OTPURI build() {
            if (paramSecret.isEmpty())
                throw new RuntimeException("No secret was provided yet it is mandatory.");

            if (accountName.isEmpty())
                accountName = "UnknownUsername";

            if (setFromAuthString) {
                if (labelIssuer.isEmpty() && paramIssuer.isEmpty()) {
                    String issuer = randomCompany();
                    labelIssuer = issuer;
                    paramIssuer = issuer;
                }
            }
			return new OTPURI(this);
		}

		private String randomCompany() {
			Random random = new Random(System.currentTimeMillis());
			int    num    = random.nextInt(1000, 9998);
			return "Unknown Company " + num;
		}
	}

	private OTPURI(Builder build) {
		this.labelIssuer    = build.labelIssuer;
		this.accountName    = build.accountName;
		this.paramSecret    = build.paramSecret;
		this.paramIssuer    = build.paramIssuer;
		this.paramAlgorithm = build.paramAlgorithm;
		this.paramDigits    = build.paramDigits;
		this.paramPeriod    = build.paramPeriod;
	}

	private String cleanSecret() {
		String sb = paramSecret;
		sb = sb.replaceFirst("\\s+", "");
		sb = sb.replaceFirst("\\.", "");
		sb = sb.replaceFirst("_", "");
		sb = sb.replaceFirst("-", "");
		sb = sb.replaceFirst("//g", "");
		sb = sb.replaceFirst("/g", "");
		return sb;
	}

	private String getLabel() {
		return "/" + labelIssuer + ":" + accountName;
	}

	private String getParameters() {
		return "secret=" + cleanSecret() +
			   ((paramIssuer.isEmpty()) ? paramIssuer : "&issuer=" + paramIssuer) +
			   ((paramAlgorithm.get().isEmpty()) ? paramAlgorithm : "&algorithm=" + paramAlgorithm) +
			   ((paramDigits.isEmpty()) ? paramDigits : "&digits=" + paramDigits) +
			   ((paramPeriod.isEmpty()) ? paramPeriod : "&period=" + paramPeriod);
	}

	/**
	 * Public Getters
	 */

	public String getOTPAuthString() {
		try {
			URI uri = new URI(resource, protocol, getLabel(), getParameters(), null);
			return uri.toASCIIString();
		}
		catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}

	public String getAuthStringDecoded() {
		return URLDecoder.decode(getOTPAuthString(), StandardCharsets.US_ASCII);
	}

	public String getAccountName() {
		return accountName;
	}

	public String getSecret() {
		return paramSecret;
	}

	public String getIssuer() {
		return paramIssuer;
	}

	public String getAlgorithm() {
		return paramAlgorithm.get();
	}

	public int getDigits() {
		return Integer.parseInt(paramDigits);
	}

	public int getPeriod() {
		return Integer.parseInt(paramPeriod);
	}

	@Override
	public String toString() {
		return getOTPAuthString();
	}
}
