package se.smhi.totp;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;

import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.LDAPResponseContext;
//import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.ldaptive.Credential;
import org.ldaptive.LdapException;
import org.ldaptive.auth.AccountState;
import org.ldaptive.auth.AuthenticationRequest;
import org.ldaptive.auth.AuthenticationResponse;
import org.ldaptive.auth.AuthenticationResultCode;
import org.ldaptive.auth.Authenticator;
import org.ldaptive.jaas.LdapPrincipal;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SMHI 2015-11-10 Victor Näslund <victor.naslund@smhi.se>
 *
 * Modified version of net.shibboleth.idp.authn.context.UsernamePasswordContext
 * Added TOTP and throttling code
 */

/**
 * An action that checks for a {@link UsernamePasswordContext} and directly produces an
 * {@link net.shibboleth.idp.authn.AuthenticationResult} based on that identity by authenticating against an LDAP.
 * 
 * @event {@link EventIds#PROCEED_EVENT_ID}
 * @event {@link EventIds#INVALID_PROFILE_CTX}
 * @event {@link AuthnEventIds#AUTHN_EXCEPTION}
 * @event {@link AuthnEventIds#ACCOUNT_WARNING}
 * @event {@link AuthnEventIds#ACCOUNT_ERROR}
 * @event {@link AuthnEventIds#INVALID_CREDENTIALS}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @pre <pre>
 * ProfileRequestContext.getSubcontext(AuthenticationContext.class).getAttemptedFlow() != null
 * </pre>
 * @post If AuthenticationContext.getSubcontext(UsernamePasswordContext.class) != null, then an
 *       {@link net.shibboleth.idp.authn.AuthenticationResult} is saved to the {@link AuthenticationContext} on a
 *       successful login. On a failed login, the
 *       {@link AbstractValidationAction#handleError(ProfileRequestContext, AuthenticationContext, String, String)}
 *       method is called.
 */
public class ValidateUsernamePasswordTOTPAgainstLDAP extends AbstractValidationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateUsernamePasswordTOTPAgainstLDAP.class);

    /** UsernamePasswordContext containing the credentials to validate. */
    @Nullable private UsernamePasswordTOTPContext upContext;

    /** LDAP authenticator. */
    @Nonnull private Authenticator authenticator;

    /** Attributes to return from authentication. */
    @Nullable private String[] returnAttributes;

    /** Authentication response associated with the login. */
    @Nullable private AuthenticationResponse response;

    /**
     * Returns the authenticator.
     * 
     * @return authenticator
     */
    @NonnullAfterInit public Authenticator getAuthenticator() {
        return authenticator;
    }

    /**
     * Sets the authenticator.
     * 
     * @param auth to authenticate with
     */
    public void setAuthenticator(@Nonnull final Authenticator auth) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        authenticator = Constraint.isNotNull(auth, "Authenticator cannot be null");
    }

    /**
     * Returns the return attributes.
     * 
     * @return attribute names
     */
    @Nullable public String[] getReturnAttributes() {
        return returnAttributes;
    }

    /**
     * Sets the return attributes.
     * 
     * @param attributes attribute names
     */
    public void setReturnAttributes(@Nullable final String... attributes) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        returnAttributes = attributes;
    }

    /** {@inheritDoc} */
    @Override protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (authenticator == null) {
            throw new ComponentInitializationException("Authenticator cannot be null");
        }
    }

    /** {@inheritDoc} */
    @Override protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }

        if (authenticationContext.getAttemptedFlow() == null) {
            log.debug("{} No attempted flow within authentication context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }

        upContext = authenticationContext.getSubcontext(UsernamePasswordTOTPContext.class);
        if (upContext == null) {
            log.info("{} No UsernamePasswordContext available within authentication context", getLogPrefix());
            handleError(profileRequestContext, authenticationContext, "NoCredentials", AuthnEventIds.NO_CREDENTIALS);
            return false;
        } else if (upContext.getUsername() == null) {
            log.info("{} No username available within UsernamePasswordContext", getLogPrefix());
            handleError(profileRequestContext, authenticationContext, "NoCredentials", AuthnEventIds.NO_CREDENTIALS);
            return false;
        } else if (upContext.getPassword() == null) {
            log.info("{} No password available within UsernamePasswordContext", getLogPrefix());
            handleError(profileRequestContext, authenticationContext, "InvalidCredentials",
                        AuthnEventIds.INVALID_CREDENTIALS);
            return false;
        } else if (upContext.getTOTPCode() == null || upContext.getTOTPCode().length() != 6) {
            log.info("{} No OTPcode available within UsernamePasswordContext", getLogPrefix());
            handleError(profileRequestContext, authenticationContext, "InvalidCredentials",
                        AuthnEventIds.INVALID_CREDENTIALS);
            return false;

            // Validate ipaddress throttle
        } else if (!TOTPThrottle.validateIPAddress(upContext.getIPAddress())) {
            log.info("{} User '{}' failed IP address throttling check - IP adress: '{}'",
                     getLogPrefix(), upContext.getUsername(), upContext.getIPAddress());
            handleError(profileRequestContext, authenticationContext, "ThrottledIPAddress",
                        AuthnEventIds.INVALID_CREDENTIALS);
            return false;

            // Validate username throttle
        } else if (!TOTPThrottle.validateUsername(upContext.getUsername())) {
            log.info("{} User '{}' failed username throttling check - IP adress: '{}'",
                     getLogPrefix(), upContext.getUsername(), upContext.getIPAddress());
            handleError(profileRequestContext, authenticationContext, "ThrottledUsername",
                        AuthnEventIds.INVALID_CREDENTIALS);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        try {
            log.debug("{} Attempting to authenticate user {}", getLogPrefix(), upContext.getUsername());
            final AuthenticationRequest request =
                    new AuthenticationRequest(upContext.getUsername(), new Credential(upContext.getPassword()),
                            returnAttributes);
            response = authenticator.authenticate(request);
            log.debug("{} Authentication response {}", getLogPrefix(), response);
            if (response.getResult()) {

                // Create LDAP object
                final TOTPReadConfigFile TOTPConfig = new TOTPReadConfigFile();
                final TOTPLDAP ldapobj = new TOTPLDAP(upContext.getUsername(), TOTPConfig.getConfig("LDAPAttribute"));

                // Process the TOTP data from LDAP
                ldapobj.setResult(response.getLdapEntry().toString());

                // Create an AES object
                final TOTPAES aesobj = new TOTPAES(upContext.getUsername(), ldapobj.getCurrentSalt(), ldapobj.getCurrentIV());

                // Debug all TOTP
                log.debug("{} Authentication using TOTP username {}", getLogPrefix(), upContext.getUsername());
                log.debug("{} Authentication using TOTP salt {}", getLogPrefix(), ldapobj.getCurrentSalt());
                log.debug("{} Authentication using TOTP iv {}", getLogPrefix(), ldapobj.getCurrentIV());
                log.debug("{} Authentication using TOTP secret {}", getLogPrefix(), ldapobj.getCurrentEncryptedTOTPSecret());
                log.debug("{} Authentication using TOTP decrypted secret {}", getLogPrefix(), aesobj.decrypt(ldapobj.getCurrentEncryptedTOTPSecret()));
                log.debug("{} Authentication using TOTP user entered TOTPCode {}", getLogPrefix(), upContext.getTOTPCode());

                // Validate TOTP code
                if (TOTPValidate.validate(aesobj.decrypt(ldapobj.getCurrentEncryptedTOTPSecret()), upContext.getTOTPCode())) {
                    log.info("{} User '{}' passed TOTP check", getLogPrefix(), upContext.getUsername());

                    // Ok to clear username and IP throttling now when client had correct credentials
                    TOTPThrottle.clearUsernameAndIP(upContext.getUsername(), upContext.getIPAddress());

                    authenticationContext.getSubcontext(LDAPResponseContext.class, true)
                        .setAuthenticationResponse(response);
                } else {
                    log.info("{} User '{}' failed TOTP check", getLogPrefix(), upContext.getUsername());
                    authenticationContext.getSubcontext(LDAPResponseContext.class, true)
                        .setAuthenticationResponse(response);
                    handleError(profileRequestContext, authenticationContext, "InvalidCredentials",
                                AuthnEventIds.INVALID_CREDENTIALS);
                }

                if (response.getAccountState() != null) {
                    final AccountState.Error error = response.getAccountState().getError();
                    handleWarning(
                            profileRequestContext,
                            authenticationContext,
                            String.format("%s:%s:%s", error != null ? error : "ACCOUNT_WARNING",
                                    response.getResultCode(), response.getMessage()), AuthnEventIds.ACCOUNT_WARNING);
                }
                buildAuthenticationResult(profileRequestContext, authenticationContext);
            } else {
                if (AuthenticationResultCode.DN_RESOLUTION_FAILURE == response.getAuthenticationResultCode()
                        || AuthenticationResultCode.INVALID_CREDENTIAL == response.getAuthenticationResultCode()) {
                    handleError(profileRequestContext, authenticationContext,
                            String.format("%s:%s", response.getAuthenticationResultCode(), response.getMessage()),
                            AuthnEventIds.INVALID_CREDENTIALS);
                } else if (response.getAccountState() != null) {
                    final AccountState state = response.getAccountState();
                    handleError(profileRequestContext, authenticationContext, String.format("%s:%s:%s",
                            state.getError(), response.getResultCode(), response.getMessage()),
                            AuthnEventIds.ACCOUNT_ERROR);
                } else {
                    handleError(profileRequestContext, authenticationContext,
                            String.format("%s:%s", response.getResultCode(), response.getMessage()),
                            AuthnEventIds.INVALID_CREDENTIALS);
                }
            }
        } catch (LdapException e) {
            log.warn("{} Login by {} produced exception", getLogPrefix(), upContext.getUsername(), e);
            handleError(profileRequestContext, authenticationContext, e, AuthnEventIds.AUTHN_EXCEPTION);
        }
    }

    /** {@inheritDoc} */
    @Override @Nonnull protected Subject populateSubject(@Nonnull final Subject subject) {
        subject.getPrincipals().add(new UsernamePrincipal(upContext.getUsername()));
        subject.getPrincipals().add(new LdapPrincipal(upContext.getUsername(), response.getLdapEntry()));
        return subject;
    }
}
