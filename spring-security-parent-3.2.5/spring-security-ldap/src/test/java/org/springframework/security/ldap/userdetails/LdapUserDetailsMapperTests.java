/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.ldap.userdetails;

import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import junit.framework.TestCase;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * Tests {@link LdapUserDetailsMapper}.
 *
 * @author Luke Taylor
 */
public class LdapUserDetailsMapperTests extends TestCase {

    public void testMultipleRoleAttributeValuesAreMappedToAuthorities() throws Exception {
        LdapUserDetailsMapper mapper = new LdapUserDetailsMapper();
        mapper.setConvertToUpperCase(false);
        mapper.setRolePrefix("");

        mapper.setRoleAttributes(new String[] {"userRole"});

        DirContextAdapter ctx = new DirContextAdapter();

        ctx.setAttributeValues("userRole", new String[] {"X", "Y", "Z"});
        ctx.setAttributeValue("uid", "ani");

        LdapUserDetailsImpl user = (LdapUserDetailsImpl) mapper.mapUserFromContext(ctx, "ani", AuthorityUtils.NO_AUTHORITIES);

        assertEquals(3, user.getAuthorities().size());
    }

    /**
     * SEC-303. Non-retrieved role attribute causes NullPointerException
     */
    public void testNonRetrievedRoleAttributeIsIgnored() throws Exception {
        LdapUserDetailsMapper mapper = new LdapUserDetailsMapper();

        mapper.setRoleAttributes(new String[] {"userRole", "nonRetrievedAttribute"});

        BasicAttributes attrs = new BasicAttributes();
        attrs.put(new BasicAttribute("userRole", "x"));

        DirContextAdapter ctx = new DirContextAdapter(attrs, new DistinguishedName("cn=someName"));
        ctx.setAttributeValue("uid", "ani");

        LdapUserDetailsImpl user = (LdapUserDetailsImpl) mapper.mapUserFromContext(ctx, "ani", AuthorityUtils.NO_AUTHORITIES);

        assertEquals(1, user.getAuthorities().size());
        assertTrue(AuthorityUtils.authorityListToSet(user.getAuthorities()).contains("ROLE_X"));
    }

    public void testPasswordAttributeIsMappedCorrectly() throws Exception {
        LdapUserDetailsMapper mapper = new LdapUserDetailsMapper();

        mapper.setPasswordAttributeName("myappsPassword");
        BasicAttributes attrs = new BasicAttributes();
        attrs.put(new BasicAttribute("myappsPassword", "mypassword".getBytes()));

        DirContextAdapter ctx = new DirContextAdapter(attrs, new DistinguishedName("cn=someName"));
        ctx.setAttributeValue("uid", "ani");

        LdapUserDetails user = (LdapUserDetailsImpl) mapper.mapUserFromContext(ctx, "ani", AuthorityUtils.NO_AUTHORITIES);

        assertEquals("mypassword", user.getPassword());
    }
}
