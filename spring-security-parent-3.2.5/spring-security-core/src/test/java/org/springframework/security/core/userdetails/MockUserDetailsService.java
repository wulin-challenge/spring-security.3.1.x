package org.springframework.security.core.userdetails;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * A test UserDetailsService containing a set of standard usernames corresponding to their account status:
 * valid, locked, disabled, credentialsExpired, expired. All passwords are "".
 *
 * @author Luke Taylor
 */
public class MockUserDetailsService implements UserDetailsService {
    private Map<String, User> users = new HashMap<String, User>();
    private List<GrantedAuthority> auths = AuthorityUtils.createAuthorityList("ROLE_USER");

    public MockUserDetailsService() {
        users.put("valid", new User("valid", "",true,true,true,true,auths));
        users.put("locked", new User("locked", "",true,true,true,false,auths));
        users.put("disabled", new User("disabled", "",false,true,true,true,auths));
        users.put("credentialsExpired", new User("credentialsExpired", "",true,true,false,true,auths));
        users.put("expired", new User("expired", "",true,false,true,true,auths));
    }

    public UserDetails loadUserByUsername(String username) {
        if (users.get(username) == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        return users.get(username);
    }
}
