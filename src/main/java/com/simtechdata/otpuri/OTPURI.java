package com.simtechdata.otpuri;

import com.warrenstrange.googleauth.GoogleAuthenticator;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static com.simtechdata.otpuri.OTPParts.*;

public class OTPURI {

	private static final String              resource = "otpauth";
	private static final String              protocol = "totp";
	private final        String              labelIssuer;
	private final        String              labelAccount;
	private final        String              paramSecret;
	private final        String              paramIssuer;
	private final        Algorithm           paramAlgorithm; //Options: SHA1, SHA256, SHA512; default = SHA1
	private final        String              paramDigits; //Number of digits to return, default = 6
	private final        String              paramPeriod; //In Seconds, default = 30
	private final        GoogleAuthenticator gAuth;

	/**
	 * Builder class
	 */
	public static class Builder {

		/**
		 * Default Constructor
		 */
		public Builder() {}

		/**
		 * Constructor where you can pass in the OTPAuth code retrieved from a QR code
		 *
		 * @param otpAuthString - OTPAuth String from QR Code
		 */
		public Builder(String otpAuthString) {
			Map<OTPParts, String> partsMap = getPartsMap(otpAuthString);
			if (partsMap != null) {
				for (OTPParts part : partsMap.keySet()) {
					switch (part) {
						case LABEL_ISSUER -> labelIssuer = partsMap.get(LABEL_ISSUER);
						case LABEL_ACCOUNT -> accountName = partsMap.get(LABEL_ACCOUNT);
						case PARAM_SECRET -> paramSecret = partsMap.get(PARAM_SECRET);
						case PARAM_ISSUER -> paramIssuer = partsMap.get(PARAM_ISSUER);
						case PARAM_ALGORITHM -> paramAlgorithm = Algorithm.getAlgorithm(partsMap.get(PARAM_ALGORITHM));
						case PARAM_DIGITS -> paramDigits = partsMap.get(PARAM_DIGITS);
						case PARAM_PERIOD -> paramPeriod = partsMap.get(PARAM_PERIOD);
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
			String[] lines = finalString.replaceFirst(resource + "://(hotp|totp)/", "").replaceFirst(resource + "://(hotp|totp)", "").split("\\?");
			String   first = lines[0];
			String   last  = lines[1];
			if (first.contains(":")) {
				String[] labelParts = first.split(":");
				map.put(LABEL_ISSUER, labelParts[LABEL_ISSUER.index()]);
				map.put(LABEL_ACCOUNT, labelParts[LABEL_ACCOUNT.index()]);
			}
			else if (first.length() > 2) {
				map.put(LABEL_ACCOUNT, first);
			}
			String[] otpParameterArray = last.split("&");
			for (String otpParameter : otpParameterArray) {
				String[] parameterLabelValue = otpParameter.split("=");
				String   parameterLabel      = parameterLabelValue[0].toLowerCase();
				String   parameterValue      = parameterLabelValue[1];
				switch (parameterLabel) {
					case "secret" -> map.put(PARAM_SECRET, parameterValue);
					case "issuer" -> map.put(PARAM_ISSUER, parameterValue);
					case "algorithm" -> map.put(PARAM_ALGORITHM, parameterValue.toUpperCase());
					case "digits" -> map.put(PARAM_DIGITS, parameterValue);
					case "period" -> map.put(PARAM_PERIOD, parameterValue);
				}
			}
			boolean hasIssuerParameter = map.containsKey(PARAM_ISSUER);
			boolean hasIssuerLabel     = map.containsKey(LABEL_ISSUER);
			boolean addIssuerParameter = hasIssuerLabel && !hasIssuerParameter;
			boolean addIssuerLabel     = hasIssuerParameter && !hasIssuerLabel;
			if (addIssuerParameter) {map.put(PARAM_ISSUER, map.get(LABEL_ISSUER));}
			if (addIssuerLabel) {map.put(LABEL_ISSUER, map.get(PARAM_ISSUER));}
			setFromAuthString = true;
			return map;
		}

		private String    labelIssuer;
		private String    accountName;
		private String    paramSecret       = "";
		private String    paramIssuer       = "";
		private Algorithm paramAlgorithm    = Algorithm.SHA1; //Options: SHA1, SHA256, SHA512; default = SHA1
		private String    paramDigits       = "6"; //Number of digits to return, default = 6
		private String    paramPeriod       = "30"; //In Seconds, default = 30
		private boolean   setFromAuthString = false;

		/**
		 * Pass in the name of Issuer to be assigned to the Label portion of the OTPAuth String
		 *
		 * @param issuer - String
		 */
		public Builder labelIssuer(String issuer) {
			this.labelIssuer = issuer;
			return this;
		}

		/**
		 * Pass in the Issuer from the Parameter portion of the OTPAuth String.
		 * This might be different under unknown special cases
		 *
		 * @param issuer - String
		 */
		public Builder paramIssuer(String issuer) {
			this.paramIssuer = issuer;
			return this;
		}

		/**
		 * Pass in the name of the issuer to be used on both the Label and Parameter oprtion of the OTPAuth String
		 *
		 * @param issuer - String
		 */
		public Builder issuer(String issuer) {
			this.labelIssuer = issuer;
			this.paramIssuer = issuer;
			return this;
		}

		/**
		 * Pass in the account name of the account that logs into the web site
		 *
		 * @param accountName - String
		 */
		public Builder accountName(String accountName) {
			this.accountName = accountName;
			return this;
		}

		/**
		 * Pass in the secret that was generated at the time two factor authentication was enabled on the website.
		 *
		 * @param secret - String
		 */
		public Builder secret(String secret) {
			this.paramSecret = secret;
			return this;
		}

		/**
		 * Pass in the algorithm that is used to generate the One Time Password
		 * This must be of the Algorithm enum datatype
		 *
		 * @param algorithm - Algorithm enum
		 */
		public Builder algorithm(Algorithm algorithm) {
			this.paramAlgorithm = algorithm;
			return this;
		}

		/**
		 * Pass in the number of One Time Password digits what will be returned when the OTP is generated
		 *
		 * @param returnDigits - int (6, 7, or 8)
		 */
		public Builder digits(int returnDigits) {
			if (returnDigits < 6 || returnDigits > 8) {throw new RuntimeException("digits must be one of these numbers: 6, 7, or 8");}
			this.paramDigits = String.valueOf(returnDigits);
			return this;
		}

		/**
		 * Pass in the amount of time that the One Time Password will be valid
		 *
		 * @param period - int (15, 30 or 60)
		 */
		public Builder period(int period) {
			boolean valid = (period == 15) || (period == 30) || (period == 60);
			if (!valid) {throw new RuntimeException("period can only be 15, 30, or 60");}
			else {this.paramPeriod = String.valueOf(period);}
			return this;
		}

		/**
		 * This returns the OTPURI class that has been built with this Builder class
		 */
		public OTPURI build() {
			if (paramSecret.isEmpty()) {throw new RuntimeException("No secret was provided yet it is mandatory.");}

			if (accountName.isEmpty()) {accountName = "UnknownUsername";}

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
		this.labelAccount   = build.accountName;
		this.paramSecret    = build.paramSecret;
		this.paramIssuer    = build.paramIssuer;
		this.paramAlgorithm = build.paramAlgorithm;
		this.paramDigits    = build.paramDigits;
		this.paramPeriod    = build.paramPeriod;
		this.gAuth          = new GoogleAuthenticator();
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
		return "/" + labelIssuer + ":" + labelAccount;
	}

	private String getParameters() {
		return "secret=" + cleanSecret() +
			   ((paramIssuer.isEmpty()) ? paramIssuer : "&issuer=" + paramIssuer) +
			   ((paramAlgorithm.get().isEmpty()) ? paramAlgorithm : "&algorithm=" + paramAlgorithm) +
			   ((paramDigits.isEmpty()) ? paramDigits : "&digits=" + paramDigits) +
			   ((paramPeriod.isEmpty()) ? paramPeriod : "&period=" + paramPeriod);
	}

	private String formatOTPString(String otpString) {
		int digits = Integer.parseInt(paramDigits);
		int delta  = digits - otpString.length();
		return "0".repeat(Math.max(0, delta)) + otpString;
	}

	private String splitOTP(String otpString) {
		String otpLeft  = "";
		String otpRight = "";
		switch (paramDigits) {
			case "6" -> {
				otpLeft  = otpString.substring(0, 3);
				otpRight = otpString.substring(3, 6);
			}
			case "7" -> {
				otpLeft  = otpString.substring(0, 3);
				otpRight = otpString.substring(3, 7);
			}
			case "8" -> {
				otpLeft  = otpString.substring(0, 4);
				otpRight = otpString.substring(4, 8);
			}
		}
		return otpLeft + "-" + otpRight;
	}

	/**
	 * gets the HTML formatted OTPAuth
	 *
	 * @return - String
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

	/**
	 * gets the friendly formatted OTPAuth (not HTML formatted)
	 *
	 * @return - String
	 */
	public String getOTPAuthStringDecoded() {
		return URLDecoder.decode(getOTPAuthString(), StandardCharsets.US_ASCII);
	}

	/**
	 * gets the account name portion of the OTPAuth
	 *
	 * @return - String
	 */
	public String getLabelAccount() {
		return labelAccount;
	}

	/**
	 * gets the secret key used to generate the synchronized One Time Password
	 *
	 * @return - String
	 */
	public String getSecret() {
		return paramSecret;
	}

	/**
	 * gets the Issuer from the OTPAuth String
	 *
	 * @return - String
	 */
	public String getIssuer() {
		return paramIssuer;
	}

	/**
	 * gets the algorithm from the OTPAuth String
	 *
	 * @return - String
	 */
	public String getAlgorithm() {
		return paramAlgorithm.get();
	}

	/**
	 * gets the number of digits that the One Time Password algorithm should generate
	 *
	 * @return - int (6, 7 or 8)
	 */
	public int getDigits() {
		return Integer.parseInt(paramDigits);
	}

	/**
	 * gets the period of time when the user can enter the One Time Password before the password expires
	 *
	 * @return - int (15, 30 or 60)
	 */
	public int getPeriod() {
		return Integer.parseInt(paramPeriod);
	}

	/**
	 * gets the current One Time Password for the assigned secret.
	 *
	 * @return - String
	 */
	public String getOTPString() {
		return formatOTPString(String.valueOf(gAuth.getTotpPassword(this.paramSecret)));
	}

	/**
	 * gets the One Time Password for the assigned secret, based on the time value passed in as argument.
	 *
	 * @param time - long
	 * @return - String
	 */
	public String getOTPString(long time) {
		return formatOTPString(String.valueOf(gAuth.getTotpPassword(this.paramSecret, time)));
	}


	/**
	 * Same as getOTPString() only it will insert a dash(-) at the mid-point.
	 *
	 * @return - String
	 */
	public String getOTPSplit() {
		String otpString = formatOTPString(String.valueOf(gAuth.getTotpPassword(this.paramSecret)));
		return splitOTP(otpString);
	}

	/**
	 * Same as getOTPString(long time) only it will insert a dash(-) at the mid-point.
	 *
	 * @return - String
	 */
	public String getOTPSplit(long time) {
		String otpString = formatOTPString(String.valueOf(gAuth.getTotpPassword(this.paramSecret, time)));
		return splitOTP(otpString);
	}

	/**
	 * gets the current One Time Password for the assigned secret.
	 *
	 * @return - int
	 */
	public int getOTP() {
		return gAuth.getTotpPassword(this.paramSecret);
	}

	/**
	 * gets the One Time Password for the assigned secret, based on the time value passed in as argument.
	 *
	 * @param time - long
	 * @return - int
	 */
	public int getOTP(long time) {
		return gAuth.getTotpPassword(this.paramSecret, time);
	}

	/**
	 * Overriden toString which will return the HTML formatted version of the OTPAuth String
	 *
	 * @return - String
	 */
	@Override
	public String toString() {
		return getOTPAuthString();
	}
}
