/**
 *
 */
package org.springframework.security.authentication.dao;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;

public class MockUserCache implements UserCache {
    private Map<String, UserDetails> cache = new HashMap<String, UserDetails>();

    public UserDetails getUserFromCache(String username) {
        return (User) cache.get(username);
    }

    public void putUserInCache(UserDetails user) {
        cache.put(user.getUsername(), user);
    }

    public void removeUserFromCache(String username) {
        cache.remove(username);
    }
}
