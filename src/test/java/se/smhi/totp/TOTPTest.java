package se.smhi.totp;

import org.junit.Test;
import org.junit.Assert;
import java.util.ArrayList;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * SMHI 2016-09-11 Victor Näslund <victor.naslund@smhi.se>
 *
 * Test our code
 * Test to encrypt and decrypt
 * Test to generate 6 digit TOTP codes from secret
 * Finally test to validate the 6 digit TOTP codes
 *
 * The response string looks like what shibboleth-idp gets from LDAP
 * when shibboleth-idp is configured to get the attributes cn and TOTPAttribute
 *
 * To generate your encrypted secret, salt and IV uncomment this line
 * at the end of function testValidateTOTPCode
 * generateSecretSaltIvForLDAP("my_username", "AAAAAAAAAAAAAAAA");
 */

public class TOTPTest {

    private final String username = "testuser";
    private final String LDAPAttribute = "TOTPAttribute";
    private final String TOTPSecret = "AAAAAAAAAAAAAAAA";
    private final String response = "[dn=CN=testuser,OU=xxx,DC=xx,DC=smhi,DC=se[[cn[testuser]], [TOTPAttribute[Salt1: oclWAzb/1t644EUfFxTzx6HBHspC2kv0DtSYDfPlSn0=, Salt0: 2qjnzFbXrDIgyKXtwg14bAmjWCgUcghdSd0mVyArkX0=, Secret0: ABoH44NmdkwKgTvbhGZ/4/tGLFznc/TDlWHH8bjJ+3o=, Secret1: l98EQeJ0i73oLiszoWdsQ5aQS2Jrx+txgOY3JvJchnI=, Iv0: /34Z0ksDAoiUBzMOrmJ+Gg==, Iv1: T8LMQV4DSoTPAHYQzR2DBQ==]]], responseControls=null, messageId=-1], accountState=null, result=true, resultCode=SUCCESS, message=null, controls=null]";

    @Test
    public void testEncryptAndDecrypt() {
        // Create an empty list we dont need old IVs or old salts
        final ArrayList<String> emptyList = new ArrayList<String>();

        // Create an AES object
        final TOTPAES aesobj = new TOTPAES(username, emptyList, emptyList);

        // Try to encrypt
        final String encryptedSecret = aesobj.encrypt(TOTPSecret);
        Assert.assertNotEquals(null, encryptedSecret);

        // Try to decrypt
        final String decryptedSecret = aesobj.decrypt(encryptedSecret);
        Assert.assertNotEquals(null, decryptedSecret);
        Assert.assertEquals(TOTPSecret, decryptedSecret);

        // Print OK
        System.out.println("Test test_EncryptAndDecrypt was OK");
    }

    @Test
    public void testLDAPDecrypt() {
        // Create LDAP object
        final TOTPLDAP ldapobj = new TOTPLDAP(username, LDAPAttribute);

        // Process the TOTP data from LDAP
        ldapobj.setResult(response);

        // Create an AES object
        final TOTPAES aesobj = new TOTPAES(username, ldapobj.getCurrentSalt(), ldapobj.getCurrentIV());

        // Try to decrypt
        final String decryptedSecret = aesobj.decrypt(ldapobj.getCurrentEncryptedTOTPSecret());
        Assert.assertNotEquals(null, decryptedSecret);
        Assert.assertEquals(TOTPSecret, decryptedSecret);

        // Print OK
        System.out.println("Test test_LDAPDecrypt was OK");
    }

    @Test
    public void testValidateTOTPCode() {

        // Create LDAP object
        final TOTPLDAP ldapobj = new TOTPLDAP(username, LDAPAttribute);

        // Process the TOTP data from LDAP
        ldapobj.setResult(response);

        // Create an AES object
        final TOTPAES aesobj = new TOTPAES(username, ldapobj.getCurrentSalt(), ldapobj.getCurrentIV());

        // Try to decrypt
        final String decryptedSecret = aesobj.decrypt(ldapobj.getCurrentEncryptedTOTPSecret());
        Assert.assertNotEquals(null, decryptedSecret);
        Assert.assertEquals(TOTPSecret, decryptedSecret);

        try {
            // Convert the TOTP secret key to correct format
            final byte[] keyBytes = Base32String.decode(TOTPSecret);
            final Mac mac = Mac.getInstance("HMACSHA1");

            mac.init(new SecretKeySpec(keyBytes, ""));

            final PasscodeGenerator pcg = new PasscodeGenerator(mac);

            // Generate the 6 digit TOTP code
            final String GeneratedTOTPCode = pcg.generateTimeoutCode();

            // TOTP codes are always 6 digits
            Assert.assertEquals(6, GeneratedTOTPCode.length());

            // Validate the 6 digit TOTP code
            final boolean TOTPCodeWasValid = TOTPValidate.validate(decryptedSecret, GeneratedTOTPCode);
            Assert.assertEquals(true, TOTPCodeWasValid);

            // Print OK
            System.out.println("Test test_ValidateTOTPCode was OK");

        } catch (final Exception e) {
            e.printStackTrace();
        }

        /*
         ########### GENERATE MY ENCRYPTED SECRET, SALT AND IV ##########################
         my_username is your username and AAAAAAAAAAAAAAAA is your TOTP secret
         That is the secret you write in your TOTP device such as
         a phone with the google Authenticator app, outcomment the line below

         generateSecretSaltIvForLDAP("my_username", "AAAAAAAAAAAAAAAA");

        /########### GENERATE MY ENCRYPTED SECRET, SALT AND IV ##########################
        */
    }

    public void generateSecretSaltIvForLDAP(final String username, final String TOTPSecret) {
        // Create an empty list we dont need old IVs or old salts
        final ArrayList<String> emptyList = new ArrayList<String>();

        // Create an AES object
        final TOTPAES aesobj = new TOTPAES(username, emptyList, emptyList);

        // Try to encrypt
        final String encryptedSecret = aesobj.encrypt(TOTPSecret);

        System.out.println("\nHere are the generated TOTP encrypted secret, salt and IV as you wanted");

        System.out.println("Secret was: " + encryptedSecret);
        System.out.println("Salt was: " + aesobj.getSalt());
        System.out.println("IV was: " + aesobj.getIV());

        System.out.println("\nTo use these values write them to your LDAP attirbute " 
                           + LDAPAttribute + "\nDo not forgot to add the type and the serialnumber as below\n");

        System.out.println("THe LDAP multivalue attribute with serial and all should be like this:\n");
        System.out.println("Secret0: " + encryptedSecret);
        System.out.println("Salt0: " + aesobj.getSalt());
        System.out.println("Iv0: " + aesobj.getIV());
        System.out.println("");
    }
}
