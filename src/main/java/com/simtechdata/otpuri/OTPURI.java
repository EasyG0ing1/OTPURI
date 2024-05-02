package com.simtechdata.otpuri;

import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.warrenstrange.googleauth.GoogleAuthenticator;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.simtechdata.otpuri.OTPParts.*;

public class OTPURI {

    private static final String resource = "otpauth";
    private static final String protocol = "totp";
    private final int dbId;
    private String labelIssuer;
    private String labelAccount;
    private String paramSecret;
    private String paramIssuer;
    private Algorithm paramAlgorithm; //Options: SHA1, SHA256, SHA512; default = SHA1
    private String paramDigits; //Number of digits to return, default = 6
    private String paramPeriod; //In Seconds, default = 30
    private String loginURL;
    private String loginUsername;
    private String loginPassword;
    private String notes;
    private final GoogleAuthenticator gAuth;

    /**
     * Builder class
     */
    public static class Builder {

        /**
         * Default Constructor
         */
        public Builder() {
        }

        /**
         * Constructor where you can pass in the OTPAuth code retrieved from a QR code
         *
         * @param otpAuthString - OTPAuth String from QR Code
         */
        public Builder(String otpAuthString) {
            this.otpAuthString = otpAuthString;
        }

        public Builder(int dbId, String otpAuthString) {
            this.dbId = dbId;
            this.otpAuthString = otpAuthString;
        }

        /**
         * This constructor can be used to create a new instance based on an existing instance
         * where the values are identical to the instance passed in as argument.
         * @param otpuri an instance of this class
         */
        public Builder(OTPURI otpuri) {
            this.dbId = otpuri.dbId;
            this.labelIssuer = otpuri.labelIssuer;
            this.labelAccount = otpuri.labelAccount;
            this.paramSecret = otpuri.paramSecret;
            this.paramIssuer = otpuri.paramIssuer;
            this.paramAlgorithm = otpuri.paramAlgorithm;
            this.paramDigits = otpuri.paramDigits;
            this.paramPeriod = otpuri.paramPeriod;
            this.loginURL = otpuri.loginURL;
            this.notes = otpuri.notes;
        }
        private String[] parseData(String data) {
            String[] parsed = new String[2];
            String regex = "(.+)(\\()(.+)(\\))";
            Pattern p = Pattern.compile(regex);
            Matcher m = p.matcher(data);
            if (m.matches()) {
                parsed[0] = m.group(3);
                parsed[1] = m.group(1);
            }
            else {
                parsed[0] = "";
                parsed[1] = "";
            }
            return parsed;
        }

        private Map<OTPParts, String> getPartsMap() {
            Map<OTPParts, String> map = new HashMap<>();
            String finalString = URLDecoder.decode(otpAuthString, StandardCharsets.ISO_8859_1);
            if (!finalString.contains(resource)) {
                return null;
            }
            String[] lines = finalString.replaceFirst(resource + "://(hotp|totp)/", "").replaceFirst(resource + "://(hotp|totp)", "").split("\\?");
            String first = lines[0];
            String last = lines[1];

            if (first.contains("(") && first.contains(")")) {
                String[] parsed = parseData(first);
                map.put(LABEL_ISSUER, parsed[0]);
                map.put(LABEL_ACCOUNT, parsed[1]);
            }
            else if (first.contains(":")) {
                String[] labelParts = first.split(":");
                map.put(LABEL_ISSUER, labelParts[LABEL_ISSUER.index()]);
                map.put(LABEL_ACCOUNT, labelParts[LABEL_ACCOUNT.index()]);
            }
            else if (first.length() > 2) {
                if (assume.equals(Assume.ISSUER)) {
                    map.put(LABEL_ISSUER, first);
                }
                else {
                    map.put(LABEL_ACCOUNT, first);
                }
            }
            String[] otpParameterArray = last.split("&");
            for (String otpParameter : otpParameterArray) {
                String[] parameterLabelValue = otpParameter.split("=");
                String parameterLabel = parameterLabelValue[0].toLowerCase();
                String parameterValue = parameterLabelValue[1];
                switch (parameterLabel) {
                    case "secret" -> map.put(PARAM_SECRET, parameterValue);
                    case "issuer" -> map.put(PARAM_ISSUER, parameterValue);
                    case "algorithm" -> map.put(PARAM_ALGORITHM, parameterValue.toUpperCase());
                    case "digits" -> map.put(PARAM_DIGITS, parameterValue);
                    case "period" -> map.put(PARAM_PERIOD, parameterValue);
                }
            }
            boolean hasIssuerParameter = map.containsKey(PARAM_ISSUER);
            boolean hasIssuerLabel = map.containsKey(LABEL_ISSUER);
            boolean addIssuerParameter = hasIssuerLabel && !hasIssuerParameter;
            if (addIssuerParameter) {
                map.put(PARAM_ISSUER, map.get(LABEL_ISSUER));
            }
            if (hasIssuerParameter) {
                if (hasIssuerLabel) {
                    map.replace(LABEL_ISSUER, map.get(PARAM_ISSUER));
                }
                else {
                    map.put(LABEL_ISSUER, map.get(PARAM_ISSUER));
                }
            }
            setFromAuthString = true;
            return map;
        }

        private String labelIssuer = "";
        private String labelAccount = "";
        private String otpAuthString = "";
        private String paramSecret = "";
        private String paramIssuer = "";
        private Algorithm paramAlgorithm = Algorithm.SHA1; //Options: SHA1, SHA256, SHA512; default = SHA1
        private String paramDigits = "6"; //Number of digits to return, default = 6
        private String paramPeriod = "30"; //In Seconds, default = 30
        private String loginURL = "";
        private String loginUsername = "";
        private String loginPassword = "";
        private String notes = "";
        private boolean setFromAuthString = false;
        private Assume assume = Assume.USERNAME;
        private int dbId;

        /**
         * This lets you set the id number in situations where you might have the auth string stored
         * in a database table and you need to be able to reference this object by a unique id number.
         *
         * @param dbId - int
         * @return Builder
         */
        public Builder dbId(int dbId) {
            this.dbId = dbId;
            return this;
        }

        /**
         * This lets you chose the behavior if only one element is provided in an otpAuth String.
         * You can tell the library to Assume.USERNAME or Assume.COMPANY which will then place the
         * single Label element under that specific label.
         *
         * @param assume - Assume
         * @return Builder
         */
        public Builder assume(Assume assume) {
            this.assume = assume;
            return this;
        }

        /**
         * Pass in the name of Issuer to be assigned to the Label portion of the OTPAuth String
         *
         * @param issuer - String
         * @return Builder
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
         * @return Builder
         */
        public Builder paramIssuer(String issuer) {
            this.paramIssuer = issuer;
            return this;
        }

        /**
         * Pass in the name of the issuer to be used on both the Label and Parameter oprtion of the OTPAuth String
         *
         * @param issuer - String
         * @return Builder
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
         * @return Builder
         */
        public Builder accountName(String accountName) {
            this.labelAccount = accountName;
            return this;
        }

        /**
         * Pass in the secret that was generated at the time two factor authentication was enabled on the website.
         *
         * @param secret - String
         * @return Builder
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
         * @return Builder
         */
        public Builder algorithm(Algorithm algorithm) {
            this.paramAlgorithm = algorithm;
            return this;
        }

        /**
         * Pass in the number of One Time Password digits what will be returned when the OTP is generated
         *
         * @param returnDigits - int (6, 7, or 8)
         * @return Builder
         */
        public Builder digits(int returnDigits) {
            if (returnDigits < 6 || returnDigits > 8) {
                System.err.println("digits (in Builder sentence) must be one of these numbers: 6, 7, or 8");
            }
            else {
                this.paramDigits = String.valueOf(returnDigits);
            }
            return this;
        }

        /**
         * Pass in the amount of time that the One Time Password will be valid
         *
         * @param period - int (15, 30 or 60)
         * @return Builder
         */
        public Builder period(int period) {
            boolean valid = (period == 15) || (period == 30) || (period == 60);
            if (!valid) {
                System.err.println("period (in Builder sentence) can only be 15, 30, or 60");
            }
            else {
                this.paramPeriod = String.valueOf(period);
            }
            return this;
        }

        /**
         * Set the URL that has the login controls for the OTP account
         *
         * @param loginURL - String
         * @return Builder
         */
        public Builder loginURL(String loginURL) {
            this.loginURL = loginURL;
            return this;
        }

        /**
         * Set the Login Username for the service that uses the OTP
         *
         * @param loginUsername - String
         * @return Builder
         */
        public Builder loginUsername(String loginUsername) {
            this.loginUsername = loginUsername;
            return this;
        }

        /**
         * Set the Login Password for the service that uses the OTP
         *
         * @param loginPassword - String
         * @return Builder
         */
        public Builder loginPassword(String loginPassword) {
            this.loginPassword = loginPassword;
            return this;
        }

        /**
         * Set any misc notes that you wish to attach to this OTPURI object.
         *
         * @param notes - String
         * @return Builder
         */
        public Builder notes(String notes) {
            this.notes = notes;
            return this;
        }

        /**
         * This returns the OTPURI class that has been built with this Builder class
         *
         * @return OTPURI
         */
        public OTPURI build() {
            if (!otpAuthString.isEmpty()) {
                Map<OTPParts, String> partsMap = getPartsMap();
                if (partsMap != null) {
                    for (OTPParts part : partsMap.keySet()) {
                        switch (part) {
                            case LABEL_ISSUER -> labelIssuer = partsMap.get(LABEL_ISSUER);
                            case LABEL_ACCOUNT -> labelAccount = partsMap.get(LABEL_ACCOUNT);
                            case PARAM_SECRET -> paramSecret = partsMap.get(PARAM_SECRET);
                            case PARAM_ISSUER -> paramIssuer = partsMap.get(PARAM_ISSUER);
                            case PARAM_ALGORITHM ->
                                    paramAlgorithm = Algorithm.getAlgorithm(partsMap.get(PARAM_ALGORITHM));
                            case PARAM_DIGITS -> paramDigits = partsMap.get(PARAM_DIGITS);
                            case PARAM_PERIOD -> paramPeriod = partsMap.get(PARAM_PERIOD);
                        }
                    }
                }
                if (paramSecret.isEmpty()) {
                    System.err.println("No secret (in OTPURI Build sentence) was provided yet it is mandatory.");
                    return null;
                }

                if (labelAccount.isEmpty()) {
                    labelAccount = "UnknownUsername";
                }

                if (setFromAuthString) {
                    String issuer = randomCompany();
                    boolean issuerEmpty = (labelIssuer == null) ? true : labelIssuer.isEmpty();
                    boolean paramIssuerEmpty = (paramIssuer == null) ? true : paramIssuer.isEmpty();
                    if (issuerEmpty) {
                        labelIssuer = issuer;
                    }
                    if (paramIssuerEmpty) {
                        paramIssuer = issuer;
                    }
                }
            }
            return new OTPURI(this);
        }

        private String randomCompany() {
            Random random = new Random(System.currentTimeMillis());
            int num = random.nextInt(1000, 9998);
            return "Unknown Company " + num;
        }
    }

    private OTPURI(Builder build) {
        this.dbId = build.dbId;
        this.labelIssuer = build.labelIssuer;
        this.labelAccount = build.labelAccount;
        this.paramSecret = build.paramSecret;
        this.paramIssuer = build.paramIssuer;
        this.paramAlgorithm = build.paramAlgorithm;
        this.paramDigits = build.paramDigits;
        this.paramPeriod = build.paramPeriod;
        this.loginURL = build.loginURL;
        this.loginUsername = build.loginUsername;
        this.loginPassword = build.loginPassword;
        this.notes = build.notes;
        this.gAuth = new GoogleAuthenticator();
    }

    public static OTPURI fromImage(File qrCodeFile) throws NotFoundException, IOException {
        String otpAuth = decodeBufferedQRImage(qrCodeFile);
        OTPURI otpuri = null;
        if (!otpAuth.isEmpty()) {
            otpuri = new OTPURI.Builder(otpAuth).build();
        }
        return otpuri;
    }

    private static String decodeBufferedQRImage(File qrCodeFile) throws IOException, NotFoundException {
        Result result;
        BufferedImage bufferedImage = ImageIO.read(qrCodeFile);
        LuminanceSource source = new BufferedImageLuminanceSource(bufferedImage);
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
        result = new MultiFormatReader().decode(bitmap);
        return (result == null) ? "" : result.getText();
    }

    private static String decodeBufferedQRImage(BufferedImage bufferedImage) {
        Result result;
        try {
            LuminanceSource source = new BufferedImageLuminanceSource(bufferedImage);
            BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
            result = new MultiFormatReader().decode(bitmap);
        } catch (NotFoundException e) {
            return "";
        }
        return (result == null) ? "" : result.getText();
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

    private String zeroPadding(String otpString) {
        int digits = Integer.parseInt(paramDigits);
        int delta = digits - otpString.length();
        return "0".repeat(Math.max(0, delta)) + otpString;
    }

    private String splitOTP(String otpString) {
        String otpLeft = "";
        String otpRight = "";
        switch (paramDigits) {
            case "6" -> {
                otpLeft = otpString.substring(0, 3);
                otpRight = otpString.substring(3, 6);
            }
            case "7" -> {
                otpLeft = otpString.substring(0, 3);
                otpRight = otpString.substring(3, 7);
            }
            case "8" -> {
                otpLeft = otpString.substring(0, 4);
                otpRight = otpString.substring(4, 8);
            }
        }
        return otpLeft + "-" + otpRight;
    }


    /**
     * It can be beneficial in the interest of ensuring you do not keep duplicate OTPAuth Strings in memory,
     * to be able to compare this class instance against another instance of this class to find out if the
     * OTPAuth Strings are the same. And that is what this methods does.
     *
     * @param otpuri - an OTPURI instance
     * @return - true if argument is same as instance
     */
    public boolean equals(OTPURI otpuri) {
        return this.toString().equals(otpuri.toString());
    }

    /**
     * Sometimes it's nice to know if two OTPURI objects have the same secret where other aspects
     * of the object might be different from one another. This will tell you with absolute certainty
     * if teo OTPURI objects are the same at their core level.
     *
     * @param otpuri - an OTPURI instance
     * @return - true if this secret is same as instance
     */
    public boolean sameSecret(OTPURI otpuri) {
        return this.getSecret().equals(otpuri.getSecret());
    }

    /**
     * Optional database ID that you can set on this object.
     *
     * @return - int
     */
    public int getDbId() {
        return dbId;
    }

    /**
     * gets the HTML formatted OTPAuth
     *
     * @return - String
     */
    public String getOTPAuthString() throws URISyntaxException {
        URI uri = new URI(resource, protocol, getLabel(), getParameters(), null);
        return uri.toASCIIString();
    }

    /**
     * gets the friendly formatted OTPAuth (not HTML formatted)
     *
     * @return - String
     */
    public String getOTPAuthStringDecoded() throws URISyntaxException {
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
        return (labelIssuer.isEmpty() ? paramIssuer : labelIssuer);
    }

    /**
     * gets the Issuer assigned to the label
     *
     * @return - String
     */
    public String getLabelIssuer() {
        return labelIssuer;
    }

    /**
     * gets the Issuer assigned to the parameter
     *
     * @return - String
     */
    public String getParamIssuer() {
        return paramIssuer;
    }

    /**
     * gets the algorithm from the OTPAuth String
     *
     * @return - String
     */
    public String getAlgorithmString() {
        return paramAlgorithm.get();
    }

    /**
     * gets the algorithm from the OTPAuth String
     *
     * @return - Algorithm
     */
    public Algorithm getAlgorithm() {
        return paramAlgorithm;
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
        return zeroPadding(String.valueOf(gAuth.getTotpPassword(this.paramSecret)));
    }

    /**
     * gets the One Time Password for the assigned secret, based on the time value passed in as argument.
     *
     * @param time - long
     * @return - String
     */
    public String getOTPString(long time) {
        return zeroPadding(String.valueOf(gAuth.getTotpPassword(this.paramSecret, time)));
    }

    /**
     * Same as getOTPString() only it will insert a dash(-) at the mid-point.
     *
     * @return - String
     */
    public String getOTPSplit() {
        String otpString = zeroPadding(String.valueOf(gAuth.getTotpPassword(this.paramSecret)));
        return splitOTP(otpString);
    }

    /**
     * Same as getOTPString(long time) only it will insert a dash(-) at the mid-point.
     *
     * @return - String
     */
    public String getOTPSplit(long time) {
        String otpString = zeroPadding(String.valueOf(gAuth.getTotpPassword(this.paramSecret, time)));
        return splitOTP(otpString);
    }

    /**
     * gets the login URL that was assigned with setLoginURL()
     *
     * @return - String
     */
    public String getLoginURL() {
        return (loginURL != null && !loginURL.isEmpty()) ? loginURL : "";
    }

    /**
     * gets the login Username for the service that issued the OTP
     *
     * @return - String
     */
    public String getLoginUsername() {
        return (loginUsername != null && !loginUsername.isEmpty()) ? loginUsername : "";
    }

    /**
     * gets the login Password for the service that issued the OTP
     *
     * @return - String
     */
    public String getLoginPassword() {
        return (loginPassword != null && !loginPassword.isEmpty()) ? loginPassword : "";
    }

    /**
     * gets whatever text is currently in the assigned notes for the object.
     *
     * @return String
     */
    public String getNotes() {
        return notes;
    }

    /**
     * Set the Issuer for the Label
     *
     * @param issuer - String
     */
    public void setLabelIssuer(String issuer) {
        this.labelIssuer = issuer;
    }

    /**
     * Set the user login name for the Label
     *
     * @param account - String
     */
    public void setAccount(String account) {
        this.labelAccount = account;
    }

    /**
     * Set the Secret for the OTP
     *
     * @param secret - String
     */
    public void setSecret(String secret) {
        this.paramSecret = secret;
    }

    /**
     * Set the Issuer for the parameter
     *
     * @param issuer - String
     */
    public void setParamIssuer(String issuer) {
        this.paramIssuer = issuer;
    }

    /**
     * Set the algorithm
     *
     * @param algorithm - Algorithm
     */
    public void setAlgorithm(Algorithm algorithm) {
        this.paramAlgorithm = algorithm;
    }

    /**
     * set the number of digits
     * Must be either 6, 7, or 8
     *
     * @param digits - Integer
     */
    public void setDigits(Integer digits) {
        this.paramDigits = String.valueOf(digits);
    }

    /**
     * Set the period of time before password times out
     * Must be either 15, 30, or 60
     *
     * @param period - Integer
     */
    public void setPeriod(Integer period) {
        this.paramPeriod = String.valueOf(period);
    }

    /**
     * Use this to set the loginURL for the site this OTPAuth was generated for.
     *
     * @param loginURL - String
     */
    public void setLoginURL(String loginURL) {
        this.loginURL = loginURL;
    }

    /**
     * Use this to set the loginURL for the site this OTPAuth was generated for.
     *
     * @param loginUsername - String
     */
    public void setLoginUsername(String loginUsername) {
        this.loginUsername = loginUsername;
    }

    /**
     * Use this to set the loginURL for the site this OTPAuth was generated for.
     *
     * @param loginPassword - String
     */
    public void setLoginPassword(String loginPassword) {
        this.loginPassword = loginPassword;
    }

    /**
     * Use this to set any misc notes you wish to assign to this OTPURI object.
     *
     * @param notes - String
     */
    public void setNotes(String notes) {
        this.notes = notes;
    }

    /**
     * Use this to set BOTH the issuer for the Label and the Parameter
     *
     * @param issuer - String
     */
    public void setIssuer(String issuer) {
        this.labelIssuer = issuer;
        this.paramIssuer = issuer;
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
        try {
            return getOTPAuthString();
        } catch (URISyntaxException ignored) {
        }
        return "";
    }
}
