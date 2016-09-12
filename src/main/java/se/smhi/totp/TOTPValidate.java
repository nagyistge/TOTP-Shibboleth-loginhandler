package se.smhi.totp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * SMHI 2015-11-10 Victor Näslund <victor.naslund@smhi.se>
 *
 * Validate users TOTP codes
 * Takes their TOTP secret and their inputed TOTP code and verifies it
 */

public class TOTPValidate {

    public static boolean validate(final String TOTPSecretKey,
                                   final String TOTPCode) {
        // Validate input
        if (TOTPCode == null || TOTPCode.length() != 6 || TOTPSecretKey == null) {
            return false;
        }

        try {
            // Convert the TOTP secret key to correct format
            final byte[] keyBytes = Base32String.decode(TOTPSecretKey);
            final Mac mac = Mac.getInstance("HMACSHA1");

            mac.init(new SecretKeySpec(keyBytes, ""));

            final PasscodeGenerator pcg = new PasscodeGenerator(mac);

            // Verify the user entered TOTP code by using the secret key
            return pcg.verifyTimeoutCode(TOTPCode);

        } catch (final Exception e) {
            e.printStackTrace();
        }

        return false;
    }
}
