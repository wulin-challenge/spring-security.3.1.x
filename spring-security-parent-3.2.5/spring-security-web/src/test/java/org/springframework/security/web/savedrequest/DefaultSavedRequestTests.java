package org.springframework.security.web.savedrequest;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.security.MockPortResolver;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 *
 */
public class DefaultSavedRequestTests {

    // SEC-308, SEC-315
    @Test
    public void headersAreCaseInsensitive() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("USER-aGenT", "Mozilla");
        DefaultSavedRequest saved = new DefaultSavedRequest(request, new MockPortResolver(8080, 8443));
        assertEquals("Mozilla", saved.getHeaderValues("user-agent").get(0));
    }

    // SEC-1412
    @Test
    public void discardsIfNoneMatchHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("If-None-Match", "somehashvalue");
        DefaultSavedRequest saved = new DefaultSavedRequest(request, new MockPortResolver(8080, 8443));
        assertTrue(saved.getHeaderValues("if-none-match").isEmpty());
    }

    // TODO: Why are parameters case insensitive. I think this is a mistake
    @Test
    public void parametersAreCaseInsensitive() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("ThisIsATest", "Hi mom");
        DefaultSavedRequest saved = new DefaultSavedRequest(request, new MockPortResolver(8080, 8443));
        assertEquals("Hi mom", saved.getParameterValues("thisisatest")[0]);
    }
}
