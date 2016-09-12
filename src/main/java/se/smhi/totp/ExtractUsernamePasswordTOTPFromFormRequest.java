package se.smhi.totp;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SMHI 2015-11-11 Victor Näslund <victor.naslund@smhi.se>
 * Modified version of net.shibboleth.idp.authn.context.UsernamePasswordContext
 * Added TOTP and throttling code
 */


/**
 * An action that extracts a username and password from an HTTP form body or query string,
 * creates a {@link UsernamePasswordContext}, and attaches it to the {@link AuthenticationContext}.
 *
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class, false) != null</pre>
 * @post If getHttpServletRequest() != null, a pair of form or query parameters is
 * extracted to populate a {@link UsernamePasswordContext}.
 */

public class ExtractUsernamePasswordTOTPFromFormRequest extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ExtractUsernamePasswordTOTPFromFormRequest.class);

    /** Parameter name for TOTPCode. */
    @Nonnull @NotEmpty private String TOTPCodeFieldName;

    /** Parameter name for username. */
    @Nonnull @NotEmpty  private String usernameFieldName;

    /** Parameter name for password. */
    @Nonnull @NotEmpty private String passwordFieldName;

    /** Parameter name for SSO bypass. */
    @Nonnull @NotEmpty private String ssoBypassFieldName;


    /** Constructor. */
    ExtractUsernamePasswordTOTPFromFormRequest() {

        TOTPCodeFieldName = "TOTPCode";
        usernameFieldName = "username";
        passwordFieldName = "password";
        ssoBypassFieldName = "donotcache";

    }

    // Handle input it should only be 6 digits
    private boolean stringNotOnlyDigits(@Nonnull @NotEmpty final String TOTPCode) {
        for (int i = 0; i < TOTPCode.length(); i++) {
            if (!Character.isDigit(TOTPCode.charAt(i))) {
                return true;
            }
        }

      return false;
    }

    /**
     * Set the TOTPCode parameter name.
     *
     * @param fieldName the TOTPCode parameter name
     */
    public void setTOTPCodeFieldName(@Nonnull @NotEmpty final String fieldName) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        TOTPCodeFieldName = Constraint.isNotNull(
                StringSupport.trimOrNull(fieldName), "TOTPCode field name cannot be null or empty.");
    }

    /**
     * Set the username parameter name.
     *
     * @param fieldName the username parameter name
     */
    public void setUsernameFieldName(@Nonnull @NotEmpty final String fieldName) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        usernameFieldName = Constraint.isNotNull(
                StringSupport.trimOrNull(fieldName), "Username field name cannot be null or empty.");
    }

    /**
     * Set the password parameter name.
     *
     * @param fieldName the password parameter name
     */
    public void setPasswordFieldName(@Nonnull @NotEmpty final String fieldName) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        passwordFieldName = Constraint.isNotNull(
                StringSupport.trimOrNull(fieldName), "Password field name cannot be null or empty.");
    }

    /**
     * Set the SSO bypass parameter name.
     *
     * @param fieldName the SSO bypass parameter name
     */
    public void setSSOBypassFieldName(@Nonnull @NotEmpty final String fieldName) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        ssoBypassFieldName = Constraint.isNotNull(
                StringSupport.trimOrNull(fieldName), "SSO Bypass field name cannot be null or empty.");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        final UsernamePasswordTOTPContext upCtx = authenticationContext
            .getSubcontext(UsernamePasswordTOTPContext.class, true);
        upCtx.setUsername(null);
        upCtx.setPassword(null);
        upCtx.setTOTPCode(null);
        upCtx.setIPAddress(null);

        final HttpServletRequest request = getHttpServletRequest();

        if (request == null) {
            log.debug("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        final String username = request.getParameter(usernameFieldName);
        if (username == null || username.isEmpty()) {
            log.debug("{} No username in request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        upCtx.setUsername(applyTransforms(username));

        final String password = request.getParameter(passwordFieldName);
        if (password == null || password.isEmpty()) {
            log.debug("{} No password in request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        upCtx.setPassword(password);

        // Get TOTP code
        final String TOTPCode = request.getParameter(TOTPCodeFieldName);

        if (TOTPCode == null || TOTPCode.isEmpty()
            || TOTPCode.length() != 6 || stringNotOnlyDigits(TOTPCode)) {
            log.debug("{} No valid TOTP code in request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        upCtx.setTOTPCode(TOTPCode);

        // Get client IP
        final String IPAddress = request.getRemoteAddr();

        if (IPAddress == null || IPAddress.isEmpty()) {
            log.debug("{} No IPAddress in request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        upCtx.setIPAddress(IPAddress);

        final String donotcache = request.getParameter(ssoBypassFieldName);
        if (donotcache != null && "1".equals(donotcache)) {
            log.debug("{} Recording do-not-cache instruction in authentication context", getLogPrefix());
            authenticationContext.setResultCacheable(false);
        }
    }
}
