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

package org.springframework.security.web.servletapi;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestWrapper;

/**
 * Tests {@link SecurityContextHolderAwareRequestWrapper}.
 *
 * @author Ben Alex
 */
public class SecurityContextHolderAwareRequestWrapperTests extends TestCase {

    protected void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    public void testCorrectOperationWithStringBasedPrincipal() throws Exception {
        Authentication auth = new TestingAuthenticationToken("rod", "koala","ROLE_FOO");
        SecurityContextHolder.getContext().setAuthentication(auth);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/");

        SecurityContextHolderAwareRequestWrapper wrapper = new SecurityContextHolderAwareRequestWrapper(request, "");

        assertEquals("rod", wrapper.getRemoteUser());
        assertTrue(wrapper.isUserInRole("ROLE_FOO"));
        assertFalse(wrapper.isUserInRole("ROLE_NOT_GRANTED"));
        assertEquals(auth, wrapper.getUserPrincipal());
    }

    public void testUseOfRolePrefixMeansItIsntNeededWhenCallngIsUserInRole() {
        Authentication auth = new TestingAuthenticationToken("rod", "koala", "ROLE_FOO");
        SecurityContextHolder.getContext().setAuthentication(auth);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/");

        SecurityContextHolderAwareRequestWrapper wrapper = new SecurityContextHolderAwareRequestWrapper(request, "ROLE_");

        assertTrue(wrapper.isUserInRole("FOO"));
    }

    public void testCorrectOperationWithUserDetailsBasedPrincipal() throws Exception {
        Authentication auth = new TestingAuthenticationToken(new User("rodAsUserDetails", "koala", true, true,
                    true, true, AuthorityUtils.NO_AUTHORITIES ), "koala", "ROLE_HELLO", "ROLE_FOOBAR");
        SecurityContextHolder.getContext().setAuthentication(auth);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/");

        SecurityContextHolderAwareRequestWrapper wrapper = new SecurityContextHolderAwareRequestWrapper(request, "");

        assertEquals("rodAsUserDetails", wrapper.getRemoteUser());
        assertFalse(wrapper.isUserInRole("ROLE_FOO"));
        assertFalse(wrapper.isUserInRole("ROLE_NOT_GRANTED"));
        assertTrue(wrapper.isUserInRole("ROLE_FOOBAR"));
        assertTrue(wrapper.isUserInRole("ROLE_HELLO"));
        assertEquals(auth, wrapper.getUserPrincipal());
    }

    public void testRoleIsntHeldIfAuthenticationIsNull() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(null);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/");

        SecurityContextHolderAwareRequestWrapper wrapper = new SecurityContextHolderAwareRequestWrapper(request, "");
        assertNull(wrapper.getRemoteUser());
        assertFalse(wrapper.isUserInRole("ROLE_ANY"));
        assertNull(wrapper.getUserPrincipal());
    }

    public void testRolesArentHeldIfAuthenticationPrincipalIsNull() throws Exception {
        Authentication auth = new TestingAuthenticationToken(null, "koala","ROLE_HELLO","ROLE_FOOBAR");
        SecurityContextHolder.getContext().setAuthentication(auth);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/");

        SecurityContextHolderAwareRequestWrapper wrapper = new SecurityContextHolderAwareRequestWrapper(request, "");

        assertNull(wrapper.getRemoteUser());
        assertFalse(wrapper.isUserInRole("ROLE_HELLO")); // principal is null, so reject
        assertFalse(wrapper.isUserInRole("ROLE_FOOBAR")); // principal is null, so reject
        assertNull(wrapper.getUserPrincipal());
    }
}
