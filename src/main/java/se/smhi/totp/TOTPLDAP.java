package se.smhi.totp;

import java.util.ArrayList;

/**
 * SMHI 2015-11-13 Victor Näslund <victor.naslund@smhi.se>

 * Get IVs, salts and encrypted TOTP secrets from shibboleth-idp
 * Who in turn got it from the LDAP
 *
 * They are stored in the same LDAP attribute like:
 *
 * Secret1: cKQOyJARVTay2RfdP+EqvoeIfKhQE4NzFHQBN4dNIHg=
 * Salt1: NsNJnY3pfDuaBhITflCHwyL59TIjjuCkfcCIZFXjXF6=
 * Iv1: 75i5eWW+wMA8K4/N3CmgFr==
 * Secret0: J5DsK3Ad8k0Re+Z+4ywSvjQwR2+pmmdyMMCGbGy6yJ0=
 * Salt0: QNTzk0rSARcxjWT/lj4lekaXMeMJkLKId4OqqQF7UZI=
 * Iv0: LIOk1KgJ02dPM7WEgaLV4w==
 *
 * All of them are stored in base64 format and its possible to have several TOTP
 * tokens at one time, in this case above we have two.
 *
 * This code only returns the last TOTP token, this is by design
 * We dont want users to have multiple active TOTP tokens at the same time
 * So when a new token is created the secret, salt and iv, the serial is increased
 * This code simply returns the token with the last serial
 *
 * If you want all tokens to be active then simply modify the code
 */

public class TOTPLDAP {

    private String username;
    private String TOTPAttribute;
    private String TOTPAttributeValue;

    private String getResult() {
        return TOTPAttributeValue;
    }

    private String getUsername() {
        return username;
    }

    private void setUsername(final String user) {
        username = user;
    }

    // Get the value belonging to this pattern
    private String getValueFromAttribute(final String ldapAttribute,
                                         final String pattern) {

        int pos = ldapAttribute.indexOf(pattern);
        String value = "";

        if (pos == -1) {
            return null;
        }

        pos += pattern.length();
        while (pos < ldapAttribute.length()) {
            // Values end with either of these chars
            if (ldapAttribute.charAt(pos) == ','
                || ldapAttribute.charAt(pos) == '}'
                || ldapAttribute.charAt(pos) == ']') {
                break;
                }

            value += ldapAttribute.charAt(pos);
            pos += 1;
        }

        return value;
    }

    // Get all IVs, salts or all our secrets
    // pattern is either "Salt", "Iv" or "Secret"
    private ArrayList<String> getValuesFromAttribute(final String pattern) {
        final ArrayList<String> values = new ArrayList();
        int pos;
        int currentVersion = 0;
        String currentPattern;
        String ldapAttribute = getResult();

        do {
            currentPattern = pattern + currentVersion + ": ";
            pos = ldapAttribute.indexOf(currentPattern);

            // If human error removed a value and thus would break our chain
            // We try skip one version and try the next one
            if (pos == -1) {
                currentPattern = pattern + (currentVersion+1) + ": ";
                pos = ldapAttribute.indexOf(currentPattern);

                if (pos == -1) {
                    break;
                }
            } else {
                // We found a value
                values.add(getValueFromAttribute(ldapAttribute, currentPattern));
            }

            currentVersion++;
        } while (pos != -1);

        return values;
    }

    // Set the data we got from shibboleth-idp
    public void setResult(final String result) {
        this.TOTPAttributeValue = result;
    }

    public ArrayList<String> getIVs() {
        return getValuesFromAttribute("Iv");
    }

    public ArrayList<String> getSalts() {
        return getValuesFromAttribute("Salt");
    }

    public String getCurrentIV() {
        final ArrayList<String> ivs = getValuesFromAttribute("Iv");

        if (ivs.isEmpty()) {
            return null;
        }

        // Get the token with the last serial
        return ivs.get(ivs.size()-1);
    }

    public String getCurrentSalt() {
        final ArrayList<String> salts = getValuesFromAttribute("Salt");

        if (salts.isEmpty()) {
            return null;
        }

        // Get the token with the last serial
        return salts.get(salts.size()-1);
    }

    public String getCurrentEncryptedTOTPSecret() {
        final ArrayList<String> secrets = getValuesFromAttribute("Secret");

        if (secrets.isEmpty()) {
            return null;
        }

        // Get the token with the last serial
        return secrets.get(secrets.size()-1);
    }

    public TOTPLDAP(final String username, final String TOTPAttribute) {
        this.username = username;
        this.TOTPAttribute = TOTPAttribute;
    }
}
