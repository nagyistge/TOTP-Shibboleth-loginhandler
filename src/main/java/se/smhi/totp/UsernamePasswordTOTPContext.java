package se.smhi.totp;

import javax.annotation.Nullable;
import org.opensaml.messaging.context.BaseContext;

/**
 * SMHI 2015-11-11 Victor Näslund <victor.naslund@smhi.se>
 *
 * Modified version of net.shibboleth.idp.authn.context.UsernamePasswordContext
 * Added TOTP and throttling code
 */

/**
 * Context, usually attached to {@link AuthenticationContext},
 * that carries a username/password pair to be validated.
 */
public class UsernamePasswordTOTPContext extends BaseContext {

    /** The username. */
    private String username;

    /** The password associated with the username. */
    private String password;

    /** The TOTP code associated with the username. */
    private String TOTPCode;

    /** The IP adress of the client */
    private String IPAddress;

    /**
     * Gets the username.
     * 
     * @return the username
     */
    @Nullable public String getUsername() {
        return username;
    }

    /**
     * Sets the username.
     * 
     * @param name the username
     * 
     * @return this context
     */
    public UsernamePasswordTOTPContext setUsername(@Nullable final String name) {
        username = name;
        return this;
    }


    /**
     * Gets the TOTPCode.
     *
     * @return the username
     */
    @Nullable public String getTOTPCode() {
        return TOTPCode;
    }

    /**
     * Sets the TOTPCode.
     *
     * @param name the username
     *
     * @return this context
     */
    public UsernamePasswordTOTPContext setTOTPCode(@Nullable final String code) {
        TOTPCode = code;
        return this;
    }

    @Nullable public String getIPAddress() {
        return IPAddress;
    }

    public UsernamePasswordTOTPContext setIPAddress(@Nullable final String ip) {
        IPAddress = ip;
        return this;
    }

    /**
     * Gets the password associated with the username.
     * 
     * @return password associated with the username
     */
    @Nullable public String getPassword() {
        return password;
    }

    /**
     * Sets the password associated with the username.
     * 
     * @param pass password associated with the username
     * 
     * @return this context
     */
    public UsernamePasswordTOTPContext setPassword(@Nullable final String pass) {
        password = pass;
        return this;
    }
}
