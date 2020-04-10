package org.springframework.security.ldap;

import org.springframework.ldap.core.DistinguishedName;

/**
 * This implementation appends a name component to the <tt>userDnBase</tt> context using the
 * <tt>usernameAttributeName</tt> property. So if the <tt>uid</tt> attribute is used to store the username, and the
 * base DN is <tt>cn=users</tt> and we are creating a new user called "sam", then the DN will be
 * <tt>uid=sam,cn=users</tt>.
 *
 * @author Luke Taylor
 */
public class DefaultLdapUsernameToDnMapper implements LdapUsernameToDnMapper {
    private final String userDnBase;
    private final String usernameAttribute;

   /**
    * @param userDnBase the base name of the DN
    * @param usernameAttribute the attribute to append for the username component.
    */
    public DefaultLdapUsernameToDnMapper(String userDnBase, String usernameAttribute) {
        this.userDnBase = userDnBase;
        this.usernameAttribute = usernameAttribute;
    }

    /**
     * Assembles the Distinguished Name that should be used the given username.
     */
    public DistinguishedName buildDn(String username) {
        DistinguishedName dn = new DistinguishedName(userDnBase);

        dn.add(usernameAttribute, username);

        return dn;
    }
}
