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

package org.springframework.security.access.vote;

import junit.framework.TestCase;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AbstractAccessDecisionManager;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.core.Authentication;

import java.util.Collection;
import java.util.List;
import java.util.Vector;


/**
 * Tests {@link AbstractAccessDecisionManager}.
 *
 * @author Ben Alex
 */
@SuppressWarnings("unchecked")
public class AbstractAccessDecisionManagerTests extends TestCase {

    //~ Methods ========================================================================================================

    public void testAllowIfAccessDecisionManagerDefaults() {
        MockDecisionManagerImpl mock = new MockDecisionManagerImpl();
        assertTrue(!mock.isAllowIfAllAbstainDecisions()); // default
        mock.setAllowIfAllAbstainDecisions(true);
        assertTrue(mock.isAllowIfAllAbstainDecisions()); // changed
    }

    public void testDelegatesSupportsClassRequests() throws Exception {
        MockDecisionManagerImpl mock = new MockDecisionManagerImpl();
        List list = new Vector();
        list.add(new DenyVoter());
        list.add(new MockStringOnlyVoter());
        mock.setDecisionVoters(list);

        assertTrue(mock.supports(String.class));
        assertTrue(!mock.supports(Integer.class));
    }

    public void testDelegatesSupportsRequests() throws Exception {
        MockDecisionManagerImpl mock = new MockDecisionManagerImpl();
        List list = new Vector();
        DenyVoter voter = new DenyVoter();
        DenyAgainVoter denyVoter = new DenyAgainVoter();
        list.add(voter);
        list.add(denyVoter);
        mock.setDecisionVoters(list);

        ConfigAttribute attr = new SecurityConfig("DENY_AGAIN_FOR_SURE");
        assertTrue(mock.supports(attr));

        ConfigAttribute badAttr = new SecurityConfig("WE_DONT_SUPPORT_THIS");
        assertTrue(!mock.supports(badAttr));
    }

    public void testProperlyStoresListOfVoters() throws Exception {
        MockDecisionManagerImpl mock = new MockDecisionManagerImpl();
        List list = new Vector();
        DenyVoter voter = new DenyVoter();
        DenyAgainVoter denyVoter = new DenyAgainVoter();
        list.add(voter);
        list.add(denyVoter);
        mock.setDecisionVoters(list);
        assertEquals(list.size(), mock.getDecisionVoters().size());
    }

    public void testRejectsEmptyList() throws Exception {
        MockDecisionManagerImpl mock = new MockDecisionManagerImpl();
        List list = new Vector();

        try {
            mock.setDecisionVoters(list);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsListContainingInvalidObjectTypes() {
        MockDecisionManagerImpl mock = new MockDecisionManagerImpl();
        List list = new Vector();
        DenyVoter voter = new DenyVoter();
        DenyAgainVoter denyVoter = new DenyAgainVoter();
        String notAVoter = "NOT_A_VOTER";
        list.add(voter);
        list.add(notAVoter);
        list.add(denyVoter);

        try {
            mock.setDecisionVoters(list);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testRejectsNullVotersList() throws Exception {
        MockDecisionManagerImpl mock = new MockDecisionManagerImpl();

        try {
            mock.setDecisionVoters(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testRoleVoterAlwaysReturnsTrueToSupports() {
        RoleVoter rv = new RoleVoter();
        assertTrue(rv.supports(String.class));
    }

    public void testWillNotStartIfDecisionVotersNotSet()
        throws Exception {
        MockDecisionManagerImpl mock = new MockDecisionManagerImpl();

        try {
            mock.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    //~ Inner Classes ==================================================================================================

    private class MockDecisionManagerImpl extends AbstractAccessDecisionManager {
        public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) {
        }
    }

    private class MockStringOnlyVoter implements AccessDecisionVoter<Object> {
        public boolean supports(Class<?> clazz) {
            return String.class.isAssignableFrom(clazz);
        }

        public boolean supports(ConfigAttribute attribute) {
            throw new UnsupportedOperationException("mock method not implemented");
        }

        public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
            throw new UnsupportedOperationException("mock method not implemented");
        }
    }
}
