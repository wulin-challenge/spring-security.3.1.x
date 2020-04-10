package org.springframework.security.web.authentication.preauth.header;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

/**
 *
 * @author Luke Taylor
 */
public class RequestHeaderAuthenticationFilterTests {

    @After
    @Before
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test(expected = PreAuthenticatedCredentialsNotFoundException.class)
    public void rejectsMissingHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();

        filter.doFilter(request, response, chain);
    }

    @Test
    public void defaultsToUsingSiteminderHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("SM_USER", "cat");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();
        filter.setAuthenticationManager(createAuthenticationManager());

        filter.doFilter(request, response, chain);
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("cat", SecurityContextHolder.getContext().getAuthentication().getName());
        assertEquals("N/A", SecurityContextHolder.getContext().getAuthentication().getCredentials());
    }

    @Test
    public void alternativeHeaderNameIsSupported() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("myUsernameHeader", "wolfman");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();
        filter.setAuthenticationManager(createAuthenticationManager());
        filter.setPrincipalRequestHeader("myUsernameHeader");

        filter.doFilter(request, response, chain);
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("wolfman", SecurityContextHolder.getContext().getAuthentication().getName());
    }

    @Test
    public void credentialsAreRetrievedIfHeaderNameIsSet() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();
        filter.setAuthenticationManager(createAuthenticationManager());
        filter.setCredentialsRequestHeader("myCredentialsHeader");
        request.addHeader("SM_USER", "cat");
        request.addHeader("myCredentialsHeader", "catspassword");

        filter.doFilter(request, response, chain);
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("catspassword", SecurityContextHolder.getContext().getAuthentication().getCredentials());
    }

    @Test
    public void userIsReauthenticatedIfPrincipalChangesAndCheckForPrincipalChangesIsSet() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();
        filter.setAuthenticationManager(createAuthenticationManager());
        filter.setCheckForPrincipalChanges(true);
        request.addHeader("SM_USER", "cat");
        filter.doFilter(request, response, new MockFilterChain());
        request = new MockHttpServletRequest();
        request.addHeader("SM_USER", "dog");
        filter.doFilter(request, response, new MockFilterChain());
        Authentication dog = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(dog);
        assertEquals("dog", dog.getName());
        // Make sure authentication doesn't occur every time (i.e. if the header *doesn't change)
        filter.setAuthenticationManager(mock(AuthenticationManager.class));
        filter.doFilter(request, response, new MockFilterChain());
        assertSame(dog, SecurityContextHolder.getContext().getAuthentication());
    }

    @Test(expected=PreAuthenticatedCredentialsNotFoundException.class)
    public void missingHeaderCausesException() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();
        filter.setAuthenticationManager(createAuthenticationManager());

        filter.doFilter(request, response, chain);
    }

    @Test
    public void missingHeaderIsIgnoredIfExceptionIfHeaderMissingIsFalse() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();
        filter.setExceptionIfHeaderMissing(false);
        filter.setAuthenticationManager(createAuthenticationManager());
        filter.doFilter(request, response, chain);
    }

    /**
     * Create an authentication manager which returns the passed in object.
     */
    private AuthenticationManager createAuthenticationManager() {
        AuthenticationManager am = mock(AuthenticationManager.class);
        when(am.authenticate(any(Authentication.class))).thenAnswer(new Answer<Authentication>() {
            public Authentication answer(InvocationOnMock invocation) throws Throwable {
                return (Authentication) invocation.getArguments()[0];
            }
        });

        return am;
    }
}
