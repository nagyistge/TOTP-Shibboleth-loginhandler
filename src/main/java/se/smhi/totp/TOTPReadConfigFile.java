package se.smhi.totp;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.Base64;

/**
 * SMHI 2016-09-08 Victor Näslund <victor.naslund@smhi.se>
 *
 * Complete rewrite of code
 *
 * The configfile contains lines in this format
 * type:value
 *
 * The value part is in base64 format so first match the type and then decode the base64 value
 */

public class TOTPReadConfigFile {

    private static String pathToConfigFile = "/opt/shibboleth-idp/credentials/totp-configfile";

    // Get the value and then decode it from base64
    private static String decodeConfigValue(final String value) {
        return new String(Base64.getDecoder().
               decode(value.substring(value.indexOf(':') + 1)));
    }

    public static String getConfig(final String config) {
        String line;

        if (config == null) {
            return "Type to read from config file was null";
        }

        try (final BufferedReader br
             = new BufferedReader(new FileReader(pathToConfigFile))) {

                // Parse config file line by line
                while ((line = br.readLine()) != null) {

                    // Ignore bad line
                    if (line.length() < 5 || line.charAt(0) == '#'
                        || line.indexOf(":") == -1) {
                        continue;
                    }

                    // Get the current type, not the value
                    final String currentType = line.substring(0, line.indexOf(':'));

                    if (currentType.equals(config)) {
                        return decodeConfigValue(line);
                    }
                }
            } catch (final Exception e) {
            e.printStackTrace();
        }

        return "Could not find that config in the configfile";
    }
}
