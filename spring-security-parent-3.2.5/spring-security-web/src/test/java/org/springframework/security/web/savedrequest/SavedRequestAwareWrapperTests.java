package org.springframework.security.web.savedrequest;

import static org.junit.Assert.*;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;

import javax.servlet.http.Cookie;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.savedrequest.FastHttpDateFormat;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequestAwareWrapper;

public class SavedRequestAwareWrapperTests {

    private SavedRequestAwareWrapper createWrapper(MockHttpServletRequest requestToSave, MockHttpServletRequest requestToWrap) {
        DefaultSavedRequest saved = new DefaultSavedRequest(requestToSave, new PortResolverImpl());
        return new SavedRequestAwareWrapper(saved, requestToWrap);
    }

    @Test
    public void savedRequestCookiesAreReturnedIfSavedRequestIsSet() throws Exception {
        MockHttpServletRequest savedRequest = new MockHttpServletRequest();
        savedRequest.setCookies(new Cookie[] {new Cookie("cookie", "fromsaved")});
        SavedRequestAwareWrapper wrapper = createWrapper(savedRequest, new MockHttpServletRequest());
        assertEquals(1, wrapper.getCookies().length);
        assertEquals("fromsaved", wrapper.getCookies()[0].getValue());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void savedRequesthHeaderIsReturnedIfSavedRequestIsSet() throws Exception {
        MockHttpServletRequest savedRequest = new MockHttpServletRequest();
        savedRequest.addHeader("header", "savedheader");
        SavedRequestAwareWrapper wrapper = createWrapper(savedRequest, new MockHttpServletRequest());

        assertNull(wrapper.getHeader("nonexistent"));
        Enumeration headers = wrapper.getHeaders("nonexistent");
        assertFalse(headers.hasMoreElements());

        assertEquals("savedheader", wrapper.getHeader("Header"));
        headers = wrapper.getHeaders("heaDer");
        assertTrue(headers.hasMoreElements());
        assertEquals("savedheader", headers.nextElement());
        assertFalse(headers.hasMoreElements());
        assertTrue(wrapper.getHeaderNames().hasMoreElements());
        assertEquals("header", wrapper.getHeaderNames().nextElement());
    }

    @Test
    /* SEC-830. Assume we have a request to /someUrl?action=foo (the saved request)
     * and then RequestDispatcher.forward() it to /someUrl?action=bar.
     * What should action parameter be before and during the forward?
     **/
    public void wrappedRequestParameterTakesPrecedenceOverSavedRequest() {
        MockHttpServletRequest savedRequest = new MockHttpServletRequest();
        savedRequest.setParameter("action", "foo");
        MockHttpServletRequest wrappedRequest = new MockHttpServletRequest();
        SavedRequestAwareWrapper wrapper = createWrapper(savedRequest, wrappedRequest);
        assertEquals("foo", wrapper.getParameter("action"));
        // The request after forward
        wrappedRequest.setParameter("action", "bar");
        assertEquals("bar", wrapper.getParameter("action"));
        // Both values should be set, but "bar" should be first
        assertEquals(2, wrapper.getParameterValues("action").length);
        assertEquals("bar", wrapper.getParameterValues("action")[0]);
    }

    @Test
    public void savedRequestDoesntCreateDuplicateParams() {
        MockHttpServletRequest savedRequest = new MockHttpServletRequest();
        savedRequest.setParameter("action", "foo");
        MockHttpServletRequest wrappedRequest = new MockHttpServletRequest();
        wrappedRequest.setParameter("action", "foo");
        SavedRequestAwareWrapper wrapper = createWrapper(savedRequest, wrappedRequest);
        assertEquals(1, wrapper.getParameterValues("action").length);
        assertEquals(1, wrapper.getParameterMap().size());
        assertEquals(1, ((String[])wrapper.getParameterMap().get("action")).length);
    }

    @Test
    public void savedRequestHeadersTakePrecedence() {
        MockHttpServletRequest savedRequest = new MockHttpServletRequest();
        savedRequest.addHeader("Authorization","foo");
        MockHttpServletRequest wrappedRequest = new MockHttpServletRequest();
        wrappedRequest.addHeader("Authorization","bar");
        SavedRequestAwareWrapper wrapper = createWrapper(savedRequest, wrappedRequest);
        assertEquals("foo", wrapper.getHeader("Authorization"));
    }

    @Test
    public void getParameterValuesReturnsNullIfParameterIsntSet() {
        SavedRequestAwareWrapper wrapper = createWrapper(new MockHttpServletRequest(), new MockHttpServletRequest());
        assertNull(wrapper.getParameterValues("action"));
        assertNull(wrapper.getParameterMap().get("action"));
    }

    @Test
    public void getParameterValuesReturnsCombinedSavedAndWrappedRequestValues() {
        MockHttpServletRequest savedRequest = new MockHttpServletRequest();
        savedRequest.setParameter("action", "foo");
        MockHttpServletRequest wrappedRequest = new MockHttpServletRequest();
        SavedRequestAwareWrapper wrapper = createWrapper(savedRequest, wrappedRequest);

        assertArrayEquals(new Object[] {"foo"}, wrapper.getParameterValues("action"));
        wrappedRequest.setParameter("action", "bar");
        assertArrayEquals(new Object[] {"bar","foo"}, wrapper.getParameterValues("action"));
        // Check map is consistent
        String[] valuesFromMap = (String[]) wrapper.getParameterMap().get("action");
        assertEquals(2, valuesFromMap.length);
        assertEquals("bar", valuesFromMap[0]);
    }

    @Test
    public void expecteDateHeaderIsReturnedFromSavedRequest() throws Exception {
        SimpleDateFormat formatter = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
        String nowString = FastHttpDateFormat.getCurrentDate();
        Date now = formatter.parse(nowString);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("header", nowString);
        SavedRequestAwareWrapper wrapper = createWrapper(request, new MockHttpServletRequest());
        assertEquals(now.getTime(), wrapper.getDateHeader("header"));

        assertEquals(-1L, wrapper.getDateHeader("nonexistent"));
    }

    @Test(expected=IllegalArgumentException.class)
    public void invalidDateHeaderIsRejected() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("header", "notadate");
        SavedRequestAwareWrapper wrapper = createWrapper(request, new MockHttpServletRequest());
        wrapper.getDateHeader("header");
    }

    @Test
    public void correctHttpMethodIsReturned() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("PUT", "/notused");
        SavedRequestAwareWrapper wrapper = createWrapper(request, new MockHttpServletRequest("GET", "/notused"));
        assertEquals("PUT", wrapper.getMethod());
    }

    @Test
    public void correctIntHeaderIsReturned() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("header", "999");
        request.addHeader("header", "1000");
        SavedRequestAwareWrapper wrapper = createWrapper(request, new MockHttpServletRequest());

        assertEquals(999, wrapper.getIntHeader("header"));
        assertEquals(-1, wrapper.getIntHeader("nonexistent"));
    }

}
