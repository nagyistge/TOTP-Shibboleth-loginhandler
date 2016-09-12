package se.smhi.totp;

import java.util.Iterator;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * SMHI 2015-11-10 Victor Näslund <victor.naslund@smhi.se>
 *
 * Keep two hashmaps in memory storing user attempts and time to throttle any bruteforce attempts
 * One map for usernames and one for ipaddresses
 *
 * The username hahsmap is to ensure the underlying LDAP account wont get locked
 * due to multiple failed login attempts
 *
 * We make the program slow down longer the bigger the maps are to preserve memory
 * Slowdown begin at 0 and will not impact normal users
 *
 * A lock is used to ensure integrity of our maps during maps write operations
 *

 ########### During a bruteforce attempt the memory looks like this ###########
 usernames (map)                    ipaddresses (map)
   username1 (hash)                   ipaddress1 (hash)
     count                              count
     time                               time
   username2 (hash)                   ipaddress2 (hash)
     count                              count
     time                               time
   ........                           ........
 ########### During a bruteforce attempt the memory looks like this ###########

*/

public class TOTPThrottle {

    // Throttle time in seconds 1200 = 20 minutes
    private static int throttleTime;

    // Maximum number of tries within throttleTime allowed
    private static int maxTries;

    // Simple wait in milliseconds for each loginattempt, this goes up during an
    // bruteforce attack to ensure we do not run out of memory
    // We clear old users when they successfully login or after throttleTime have passed
    private static int SLOWDOWN = 0;

    // Set this to 8192 so no need to rezise until a bruteforce attack happens
    private static final ConcurrentHashMap<String, ArrayList<String>>
        usernames = new ConcurrentHashMap<String, ArrayList<String>>(8192),
        IPAddresses = new ConcurrentHashMap<String, ArrayList<String>>(8192);

    // We need a lock to ensure integrity of our map during map operations
    private static final ReentrantLock lock = new ReentrantLock();

    // We increase the slowdown time the larger our maps are, meaning during an bruteforce attack
    // Its improbable for a resonable sized organisation to have more than 100 concurrent users
    // So this only happens during a bruteforce attack
    // As soon as a user successfully logins they are cleared from maps
    private static void updateSlowdown() {
        if (usernames.size() > 8000) {
            // 4.096 seconds
            SLOWDOWN = 4096;
        } else if (usernames.size() > 6000) {
            SLOWDOWN = 3072;
        } else if (usernames.size() > 3000) {
            SLOWDOWN = 2048;
        } else if (usernames.size() > 1000) {
            SLOWDOWN = 1024;
        } else if (usernames.size() > 100) {
            SLOWDOWN = 256;
        } else {
            SLOWDOWN = 0;
        }
    }

    private static int getMaxTries() {
        return maxTries;
    }

    private static void setMaxTries(final int tries) {
        maxTries = tries;
    }

    private static int getThrottleTime() {
        return throttleTime;
    }

    private static void setThrottleTime(final int time) {
        throttleTime = time;
    }

    // Remove old users, users that have been locked for more than throttleTime from our map
    private static void clearOld() {
        final Iterator<String> iteratorUsernames = usernames.keySet().iterator();
        final Iterator<String> iteratorIPAddresses = IPAddresses.keySet().iterator();
        final long currentTime = System.currentTimeMillis() / 1000;

        // Wait for other threads to modify our maps, then make other threads wait for us to finish
        lock.lock();

        // For all entries in our usernames map
        while (iteratorUsernames.hasNext()) {
            final ArrayList<String> list = usernames.get(iteratorUsernames.next());

            // If user is old then remove it
            if (Long.parseLong(list.get(1)) + throttleTime < currentTime) {
                iteratorUsernames.remove();
            }
        }

        // For all entries in our ipaddresses map
        while (iteratorIPAddresses.hasNext()) {
            final ArrayList<String> list = IPAddresses.get(iteratorIPAddresses.next());

            // If the IP address is old then remove it
            if (Long.parseLong(list.get(1)) + throttleTime < currentTime) {
                iteratorIPAddresses.remove();
            }
        }

        // We are done with modifying our map so we can release the lock
        lock.unlock();
    }

    private static void updateMap(final String identity,
                                  final ConcurrentHashMap<String, ArrayList<String>> map,
                                  final int count,
                                  final long time) {

        final ArrayList<String> list = new ArrayList<String>();

        // Wait for other threads to modify our maps, then make other threads wait for us to finish
        lock.lock();

        list.add(new String(Integer.toString(count)));
        list.add(new String(Long.toString(time)));
        map.put(identity, list);

        // We are done with modifying our map so we can release the lock
        lock.unlock();
    }

    private static boolean validateMap(final String identity,
                                       final ConcurrentHashMap<String, ArrayList<String>> map) {

        final long currentTime = System.currentTimeMillis() / 1000;

        try {
            // Sleep SLOWDOWN millisecond to prevent bruteforcing
            // Slowdown divided by 2 since we do this for both the username and the ipaddresses map
            Thread.sleep(SLOWDOWN/2);
        } catch (final Exception e) {
            return false;
        }

        try {
            // If user is in our map mean they failed a loginattempt in the past
            // They will be removed from our map once they pass a login attempt
            if (map.containsKey(identity)) {
                // If user failed less than maxTries times
                // Then allow and increase the count with 1
                if (Integer.parseInt(map.get(identity).get(0)) < getMaxTries()) {
                    updateMap(identity, map, Integer.
                              parseInt(map.get(identity).get(0)) + 1, currentTime);

                // User did wait ThrottleTime after last try so we allow
                // We reset the counter to 1 in the map
                } else if (Long.parseLong(map.get(identity).get(1)) + getThrottleTime() < currentTime) {
                    updateMap(identity, map, 1, currentTime);

                // User did not wait ThrottleTime after last try so we deny
                // Set count to maxTries + 1 so user must wait throttleTime before trying again
                } else {
                    updateMap(identity, map, getMaxTries() + 1, currentTime);
                    return false;
                }
            // User was not in our map
            // so we allow and set counter to 1 for that user
            } else {
                updateMap(identity, map, 1, currentTime);
            }

            return true;
        }

        // This run always, even after return statement
        finally {
            // we clear old users who last tried over THROTTLE TIME ago
            // This will make sure we dont run out of memory
            clearOld();

            // Check if our map now is large enough for us to update slowdown time
            updateSlowdown();
        }
    }

    // Look into our map and se if user should be allow to attempt to login or not
    public static boolean validateUsername(final String username) {
        // Return true if username is not bruteforcing
        return validateMap(username, usernames);
    }

    // Look into our map and se if ip should be allow to attempt to login or not
    public static boolean validateIPAddress(final String ip) {
        // Return true if ip is not bruteforcing
        return validateMap(ip, IPAddresses);
    }

    // User passed a loginattempt so we clear the user from our maps
    public static void clearUsernameAndIP(final String username, final String ip) { 
        // Wait for other threads to modify our maps, then make other threads wait for us to finish
        lock.lock();

        try {
            usernames.remove(username);
            IPAddresses.remove(ip);
        } finally {
            // We are done with modifying our map so we can release the lock
            lock.unlock();
        }
    }

    // Static initializer
    // Read the config when we create this static object
    static {
        // Set maxTries and throttleTime from config file
        final TOTPReadConfigFile TOTPConfig = new TOTPReadConfigFile();

        setMaxTries(Integer.parseInt(TOTPConfig.getConfig("TOTPMaxTries")));
        setThrottleTime(Integer.parseInt(TOTPConfig.getConfig("TOTPThrottleTime")));
    }
}
