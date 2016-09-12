# Shibboleth-TOTP-loginhandler
This project add a TOTP loginhandler for shibboleth-idp

The TOTP secret is stored encrypted in LDAP

## How to use
First install maven and java 1.8 devel.

Then create the file /opt/shibboleth-idp/credentials/totp-configfile
both on your current compiling node and the shibboleth-idp node
```bash
# Lines are in this format type:value
# Values are encoded in base64
#
# FirstPartOfTOTPAESKey and SecondPartOfTOTPAESKey
# will be used for the encryption key for the TOTP secrets stored in LDAP
# Fore more info about the encryption see TOTPAES.java
# Change them to something appropriate
#
# TOTPMaxTries is how many times one can try
# before the module start taking anti bruteforce measures
#
# TOTPThrottleTime is how many seconds the account and/or ip address
# will be locked because of anti bruteforce measures
#
# To encode the values to base64 use this
# echo -n "BBB" | base64
# Will give you QkJC
#
# To decode base64 do this
# echo "QkJC" | base64 -d

FirstPartOfTOTPAESKey:QUFB
SecondPartOfTOTPAESKey:QkJC
TOTPMaxTries:OA==
TOTPThrottleTime:MTIwMA==
```

To compile the module run

```bash
mvn clean install
```
This will give you a jar file
```bash
totp-0.99.jar
```
Copy this file to your shibboleth-idp installation like
```bash
cp totp-0.99.jar ${shibboleth-idp}/edit-webapp/WEB-INF/lib/
```
Rebuild shibboleth-idp with the module using
```bash
cd ${shibboleth-idp}
./bin/build.sh
```

### Ok now we simply have to edit some config files to enable the module

In ${shibboleth-idp}/conf/logback.xml we have this
```xml
    <!-- Logs IdP, but not OpenSAML, messages -->
    <logger name="net.shibboleth.idp" level="INFO"/>
```
Add this just below

```xml
    <!-- TOTP set to DEBUG if needed -->
    <logger name="se.smhi.totp" level="INFO"/>
```

In ${shibboleth-idp}/conf/authn/general-authn.xml we have this

```xml
    <bean id="authn/Password" parent="shibboleth.AuthenticationFlow"
          p:passiveAuthenticationSupported="true"
          p:forcedAuthenticationSupported="true" />

```
Add this just below
```xml
    <!-- TOTP -->
    <bean id="authn/TOTP" parent="shibboleth.AuthenticationFlow"
          p:passiveAuthenticationSupported="true"
          p:forcedAuthenticationSupported="true">
      <property name="supportedPrincipals">
      <util:list>
          <bean parent="shibboleth.SAML2AuthnContextClassRef"
                c:classRef="urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken" />
                </util:list>
      </property>
    </bean>
```
In ${shibboleth-idp}/conf/authn/ldap-authn-config.xml we have this line
```xml
  <alias name="ValidateUsernamePasswordAgainstLDAP" alias="ValidateUsernamePassword" />
```
Add this line below it
```xml
  <alias name="ValidateUsernamePasswordTOTPAgainstLDAP" alias="ValidateUsernamePasswordTOTP" />
```

In the file ${shibboleth-idp}/conf/ldap.properties we have idp.authn.LDAP.returnAttributes  
Edit idp.authn.LDAP.returnAttributes by adding the name of your LDAP TOTP attribute here so shibboleth fetch it during authentication  
Also edit TOTP to idp.authn.flows like

```bash
idp.authn.LDAP.returnAttributes = cn,TOTPAttribute
idp.authn.flows = Password|TOTP
```

In ${shibboleth-idp}/flows/authn/conditions/conditions-flow.xml we have this
```xml
    <action-state id="ValidateUsernamePassword">
        
        <!-- Call outs for exceptional conditions. -->
        <transition on="AccountWarning" to="CallExpiringPassword" />
        <transition on="ExpiringPassword" to="CallExpiringPassword" />
        <transition on="ExpiredPassword" to="CallExpiredPassword" />
        <transition on="AccountLocked" to="CallAccountLocked" />
        
        <transition to="DisplayUsernamePasswordPage" />
    </action-state>
```
Add this just below
```xml
    <!-- TOTP -->
    <action-state id="ValidateUsernamePasswordTOTP">
        
        <!-- Call outs for exceptional conditions. -->
        <transition on="AccountWarning" to="CallExpiringPassword" />
        <transition on="ExpiringPassword" to="CallExpiringPassword" />
        <transition on="ExpiredPassword" to="CallExpiredPassword" />
        <transition on="AccountLocked" to="CallAccountLocked" />
        
        <transition to="DisplayUsernamePasswordTOTPPage" />
    </action-state>

```

In ${shibboleth-idp}/messages/authn-messages.properties add these lines
```bash
ThrottledUsername = throttled-username
ThrottledIPAddress = throttled-ipaddress
throttled-username.message = Your account is locked for XXX (see TOTPThrottle.java file) minutes
throttled-ipaddress.message = Your IP address is locked for XXX (see TOTPThrottle.java file) minutes
```

In the file ${shibboleth-idp}/system/conf/webflow-config.xml we have this line
```xml
        <webflow:flow-location id="authn/Password" path="../system/flows/authn/password-authn-flow.xml" />
```
Add this below it
```xml
        <!-- TOTP-->
        <webflow:flow-location id="authn/TOTP" path="../system/flows/authn/totp-authn-flow.xml" />
```

Now copy the TOTP config files
```bash
cp system/flows/authn/totp-authn-beans.xml to ${shibboleth-idp}/system/flows/authn/totp-authn-beans.xml

cp system/flows/authn/totp-authn-flow.xml ${shibboleth-idp}/system/flows/authn/totp-authn-flow.xml

cp views/loginTOTP.vm ${shibboleth-idp}/views/loginTOTP.vm

cp conf/authn/totp-authn-config.xml ${shibboleth-idp}/conf/authn/totp-authn-config.xml
```

## Generate your TOTP secret
Uncomment the function call to generateSecretSaltIvForLDAP at the end of the function testValidateTOTPCode in TOTPTest.java then
```bash
mvn clean install
```

Edit your LDAP multivalue attribute and add the generated encrypted secret, salt and IV to your LDAP attribute
Add the TOTP secret to your TOTP device, for example the app Google Authenticator for Android/iPhone phones
## You should now be able to login using TOTP
