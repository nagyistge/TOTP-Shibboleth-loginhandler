package se.smhi.totp;

import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;

import java.util.ArrayList;
import java.util.Base64;

/**
 * SMHI 2015-11-13 Victor Näslund <victor.naslund@smhi.se>
 *
 * Decrypt our AES256-GCM encrypted TOTP secrets
 * Takes username and base64 encoded initialization vectors and salts
 * Username since the AES key depends on the username so every user have a unique key
 * The key is constructed by <our secret string1> + <username> + <our secret string2>
 * Then we hash the key with PBKDF2WithHmacSHA256 so we get a 256 bit key <- that is the real key
 */

public class TOTPAES {

    private String username;
    private String iv;
    private String salt;

    private void setSalt(final String s) {
        salt = s;
    }

    private void setIV(final String b) {
        iv = b;
    }

    private String getUsername() {
        return username;
    }

    private void setUsername(final String u) {
        username = u;
    }

    // Generate new IV and salt if either where previously used
    // Only used for encryption
    private boolean isSaltOrIVReused(final String salt, final ArrayList<String> salts,
                                          final String iv, final ArrayList<String> ivs) {
        // Our salt or IV are not allowed be to null
        if (salt == null || iv == null) {
            return true;
        }

        // Previous used salt or IVs can be null
        if (salts == null || ivs == null) {
            return false;
        }

        // Was IV used before?
        for (final String i : ivs) {
            if (iv.equals(i)) {
                return true;
            }
        }

        // Was salt used before?
        for (final String i : salts) {
            if (salt.equals(i)) {
                return true;
            }
        }

        return false;
    }

    // From the random string + username + randomstring
    // We create the key
    private String getKey() {
        final TOTPReadConfigFile TOTPConfig = new TOTPReadConfigFile();

        return TOTPConfig.getConfig("FirstPartOfTOTPAESKey") + getUsername()
            + TOTPConfig.getConfig("SecondPartOfTOTPAESKey");
    }

    // we create a hash from the key which we use as the actual key
    // We also salt it and do 5000 iterations
    private SecretKeySpec makeKey() {
        try {
            final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            final KeySpec spec = new PBEKeySpec(getKey().toCharArray(),
                                          getSalt().getBytes("UTF-8"), 5000, 256);
            final SecretKey tmp = factory.generateSecret(spec);

            return new SecretKeySpec(tmp.getEncoded(), "AES");

        } catch (final Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private GCMParameterSpec makeIv() {
        try {
            // AES has a blocksize of 128 bits
            return new GCMParameterSpec(128, Base64.getDecoder()
                                        .decode(getIV().getBytes("UTF-8")));

        } catch (final Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public String getSalt() {
        return salt;
    }

    public String getIV() {
        return iv;
    }

    // Return null will cause the loginflow to fail and not granting user access
    public String encrypt(final String message) {
        if (salt == null || iv == null || message == null) {
            return null;
        }

        try {
            // We use AES-GCM-256
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, makeKey(), makeIv());
            return new String(Base64.getEncoder().encode(cipher.doFinal(message.getBytes("UTF-8"))));

        } catch (final Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    // Return null will cause the loginflow to fail and not granting user access
    public String decrypt(final String message) {
        if (salt == null || iv == null || message == null) {
            return null;
        }

        try {
            // We use AES-GCM-256
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, makeKey(), makeIv());
            return new String(cipher.doFinal(Base64.getDecoder()
                                             .decode(message.getBytes("UTF-8"))));

        } catch (final Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    // This constructor should be used for decryption
    // We have only one IV, the one we get from LDAP
    public TOTPAES(final String user, final String salt, final String iv) {
        // Set key to be random string + username + random string 2
        setUsername(user);

        // Set the salt and IV
        setSalt(salt);
        setIV(iv);
    }

    // This constructor should be used for encryption
    // We want a new IV but IV is not allowed to be reused
    // We make sure IVs are not reused by passing all previously used IVs as a string array
    public TOTPAES(final String user, final ArrayList<String> salts, final ArrayList<String> ivs) {
        // "Secure" random generator
        final SecureRandom rng = new SecureRandom();

        // 16 * 8 = 128 bits which is AES blocksize
        final byte[] iv = new byte[16];

        // 32 * 8 = 256 bits our salt will be 256 bits
        final byte[] salt = new byte[32];

        // Generate new bytes for salt and IV
        rng.nextBytes(salt);
        rng.nextBytes(iv);

        // Generate new IV and salt if the "impossible" happened
        // That our generated IV or salt was identical as a previous used one
        while (isSaltOrIVReused(new String(Base64.getEncoder().encodeToString(salt)),
                                salts, new String(Base64.getEncoder().encodeToString(iv)), ivs)) { 
            rng.nextBytes(salt);
            rng.nextBytes(iv);
        }

        // Set key to be random string + username + random string 2
        setUsername(user);

        // Encode IV and salt to base64 so we can save it in LDAP
        setSalt(new String(Base64.getEncoder().encodeToString(salt)));
        setIV(new String(Base64.getEncoder().encodeToString(iv)));
    }
}
