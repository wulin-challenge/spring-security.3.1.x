package org.springframework.security.provisioning;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * An extension of the {@link UserDetailsService} which provides the ability
 * to create new users and update existing ones.
 * 
 * <p> UserDetailsService的扩展，可以创建新用户和更新现有用户。
 *
 * @author Luke Taylor
 * @since 2.0
 */
public interface UserDetailsManager extends UserDetailsService {

    /**
     * Create a new user with the supplied details.
     */
    void createUser(UserDetails user);

    /**
     * Update the specified user.
     */
    void updateUser(UserDetails user);

    /**
     * Remove the user with the given login name from the system.
     */
    void deleteUser(String username);

    /**
     * Modify the current user's password. This should change the user's password in
     * the persistent user repository (datbase, LDAP etc).
     * 
     * <p> 修改当前用户的密码。 这应该更改持久性用户存储库（datbase，LDAP等）中的用户密码。
     *
     * @param oldPassword current password (for re-authentication if required)
     * @param newPassword the password to change to
     */
    void changePassword(String oldPassword, String newPassword);

    /**
     * Check if a user with the supplied login name exists in the system.
     * 
     * <p> 检查系统中是否存在具有提供的登录名的用户。
     */
    boolean userExists(String username);

}
