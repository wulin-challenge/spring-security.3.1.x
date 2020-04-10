package org.springframework.security.web.context;

import javax.servlet.AsyncContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.web.util.WebUtils;

/**
 * A {@code SecurityContextRepository} implementation which stores the security context in the {@code HttpSession}
 * between requests.
 * 
 * <p> 一个SecurityContextRepository实现，将安全上下文存储在请求之间的HttpSession中。
 * 
 * <p>
 * The {@code HttpSession} will be queried to retrieve the {@code SecurityContext} in the <tt>loadContext</tt>
 * method (using the key {@link #SPRING_SECURITY_CONTEXT_KEY} by default). If a valid {@code SecurityContext} cannot be
 * obtained from the {@code HttpSession} for whatever reason, a fresh {@code SecurityContext} will be created
 * by calling by {@link SecurityContextHolder#createEmptyContext()} and this instance will be returned instead.
 * 
 * <p> 将查询HttpSession以在loadContext方法中检索SecurityContext（默认情况下使用键SPRING_SECURITY_CONTEXT_KEY）。
 * 如果出于任何原因都无法从HttpSession获取有效的SecurityContext，则将通过SecurityContextHolder.createEmptyContext（）
 * 调用来创建一个新的SecurityContext，并将返回该实例。
 * 
 * <p>
 * When <tt>saveContext</tt> is called, the context will be stored under the same key, provided
 * 
 * <p> 调用saveContext时，上下文将存储在相同的键下，
 * 
 * <ol>
 * <li>The value has changed</li>
 * 
 * <p> 值已更改
 * 
 * <li>The configured <tt>AuthenticationTrustResolver</tt> does not report that the contents represent an anonymous
 * user</li>
 * 
 * <p> 配置的AuthenticationTrustResolver不会报告内容代表匿名用户
 * 
 * </ol>
 * <p>
 * With the standard configuration, no {@code HttpSession} will be created during <tt>loadContext</tt> if one does
 * not already exist. When <tt>saveContext</tt> is called at the end of the web request, and no session exists, a new
 * {@code HttpSession} will <b>only</b> be created if the supplied {@code SecurityContext} is not equal
 * to an empty {@code SecurityContext} instance. This avoids needless <code>HttpSession</code> creation,
 * but automates the storage of changes made to the context during the request. Note that if
 * {@link SecurityContextPersistenceFilter} is configured to eagerly create sessions, then the session-minimisation
 * logic applied here will not make any difference. If you are using eager session creation, then you should
 * ensure that the <tt>allowSessionCreation</tt> property of this class is set to <tt>true</tt> (the default).
 * 
 * <p> 在标准配置下，如果loadContext不存在，则不会在HttpContext中创建任何HttpSession。当在Web请求的末尾调用saveContext
 * 且不存在会话时，仅在提供的SecurityContext不等于空的SecurityContext实例时，才会创建新的HttpSession。这样可以避免不必要的
 * HttpSession创建，但是可以自动存储在请求期间对上下文所做的更改。请注意，如果将SecurityContextPersistenceFilter
 * 配置为热切创建会话，则此处应用的会话最小化逻辑不会有任何区别。如果使用急切的会话创建，则应确保将此类的allowSessionCreation
 * 属性设置为true（默认值）。
 * 
 * <p>
 * If for whatever reason no {@code HttpSession} should <b>ever</b> be created (for example, if
 * Basic authentication is being used or similar clients that will never present the same {@code jsessionid}), then
 * {@link #setAllowSessionCreation(boolean) allowSessionCreation} should be set to <code>false</code>.
 * Only do this if you really need to conserve server memory and ensure all classes using the
 * {@code SecurityContextHolder} are designed to have no persistence of the {@code SecurityContext}
 * between web requests.
 * 
 * <p> 如果出于任何原因都不应该创建HttpSession（例如，如果使用基本身份验证或永远不会显示相同jsessionid的类似客户端），则应将
 * allowSessionCreation设置为false。仅在确实需要节省服务器内存并确保使用SecurityContextHolder的所有类被设计为在Web
 * 请求之间不保留SecurityContext时，才执行此操作。
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class HttpSessionSecurityContextRepository implements SecurityContextRepository {
    /**
     * The default key under which the security context will be stored in the session.
     * 
     * <p> 安全上下文将被存储在会话中的默认密钥。
     */
    public static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";

    protected final Log logger = LogFactory.getLog(this.getClass());

    /** SecurityContext instance used to check for equality with default (unauthenticated) content */
    /** 用于检查与默认（未经身份验证）内容是否相等的SecurityContext实例 */
    private final Object contextObject = SecurityContextHolder.createEmptyContext();
    private boolean allowSessionCreation = true;
    private boolean disableUrlRewriting = false;
    private boolean isServlet3 = ClassUtils.hasMethod(ServletRequest.class, "startAsync");
    private String springSecurityContextKey = SPRING_SECURITY_CONTEXT_KEY;

    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    /**
     * Gets the security context for the current request (if available) and returns it.
     * 
     * <p> 获取当前请求的安全上下文（如果有）并返回。
     * 
     * <p>
     * If the session is null, the context object is null or the context object stored in the session
     * is not an instance of {@code SecurityContext}, a new context object will be generated and
     * returned.
     * 
     * <p> 如果会话为null，上下文对象为null或会话中存储的上下文对象不是SecurityContext的实例，则将生成并返回一个新的上下文对象。
     */
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        HttpServletResponse response = requestResponseHolder.getResponse();
        HttpSession httpSession = request.getSession(false);

        SecurityContext context = readSecurityContextFromSession(httpSession);

        if (context == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("No SecurityContext was available from the HttpSession: " + httpSession +". " +
                        "A new one will be created.");
            }
            context = generateNewContext();

        }

        SaveToSessionResponseWrapper wrappedResponse = new SaveToSessionResponseWrapper(response, request, httpSession != null, context);
        requestResponseHolder.setResponse(wrappedResponse);

        if(isServlet3) {
            requestResponseHolder.setRequest(new Servlet3SaveToSessionRequestWrapper(request, wrappedResponse));
        }

        return context;
    }

    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        SaveContextOnUpdateOrErrorResponseWrapper responseWrapper = WebUtils.getNativeResponse(response, SaveContextOnUpdateOrErrorResponseWrapper.class);
        if(responseWrapper == null) {
            throw new IllegalStateException("Cannot invoke saveContext on response " + response + ". You must use the HttpRequestResponseHolder.response after invoking loadContext");
        }
        // saveContext() might already be called by the response wrapper
        // if something in the chain called sendError() or sendRedirect(). This ensures we only call it
        // once per request.
        
        // 如果链中名为sendError（）或sendRedirect（）的某个内容，则响应包装器可能已经调用了saveContext（）。 这样可以确保每个请求仅调用一次。
        if (!responseWrapper.isContextSaved() ) {
            responseWrapper.saveContext(context);
        }
    }

    public boolean containsContext(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session == null) {
            return false;
        }

        return session.getAttribute(springSecurityContextKey) != null;
    }

    /**
     *
     * @param httpSession the session obtained from the request.
     * 
     * <p> 从请求获得的会话。
     */
    private SecurityContext readSecurityContextFromSession(HttpSession httpSession) {
        final boolean debug = logger.isDebugEnabled();

        if (httpSession == null) {
            if (debug) {
                logger.debug("No HttpSession currently exists");
            }

            return null;
        }

        // Session exists, so try to obtain a context from it.
        // 会话存在，因此请尝试从中获取上下文。

        Object contextFromSession = httpSession.getAttribute(springSecurityContextKey);

        if (contextFromSession == null) {
            if (debug) {
                logger.debug("HttpSession returned null object for SPRING_SECURITY_CONTEXT");
            }

            return null;
        }

        // We now have the security context object from the session.
        // 现在，我们从会话中获得了安全上下文对象。
        if (!(contextFromSession instanceof SecurityContext)) {
            if (logger.isWarnEnabled()) {
                logger.warn(springSecurityContextKey + " did not contain a SecurityContext but contained: '"
                        + contextFromSession + "'; are you improperly modifying the HttpSession directly "
                        + "(you should always use SecurityContextHolder) or using the HttpSession attribute "
                        + "reserved for this class?");
            }

            return null;
        }

        if (debug) {
            logger.debug("Obtained a valid SecurityContext from " + springSecurityContextKey + ": '" + contextFromSession + "'");
        }

        // Everything OK. The only non-null return from this method.
        // 一切还好。 此方法唯一的非null返回。

        return (SecurityContext) contextFromSession;
    }

    /**
     * By default, calls {@link SecurityContextHolder#createEmptyContext()} to obtain a new context (there should be
     * no context present in the holder when this method is called). Using this approach the context creation
     * strategy is decided by the {@link SecurityContextHolderStrategy} in use. The default implementations
     * will return a new <tt>SecurityContextImpl</tt>.
     * 
     * <p> 默认情况下，调用SecurityContextHolder.createEmptyContext（）以获取新的上下文（调用此方法时，
     * 持有人中应该没有上下文）。 使用这种方法，上下文创建策略由使用中的SecurityContextHolderStrategy决定。 
     * 默认实现将返回一个新的SecurityContextImpl。
     *
     * @return a new SecurityContext instance. Never null.
     * 
     * <p> 一个新的SecurityContext实例。 永不为空。
     */
    protected SecurityContext generateNewContext() {
        return SecurityContextHolder.createEmptyContext();
    }

    /**
     * If set to true (the default), a session will be created (if required) to store the security context if it is
     * determined that its contents are different from the default empty context value.
     * 
     * <p> 如果设置为true（默认值），则在确定其内容不同于默认的空上下文值时，将创建一个会话（如果需要）来存储安全上下文。
     * 
     * <p>
     * Note that setting this flag to false does not prevent this class from storing the security context. If your
     * application (or another filter) creates a session, then the security context will still be stored for an
     * authenticated user.
     * 
     * <p> 请注意，将此标志设置为false不会阻止此类存储安全上下文。 如果您的应用程序（或其他过滤器）创建了会话，
     * 则仍将为经过身份验证的用户存储安全上下文。
     *
     * @param allowSessionCreation
     */
    public void setAllowSessionCreation(boolean allowSessionCreation) {
        this.allowSessionCreation = allowSessionCreation;
    }

    /**
     * Allows the use of session identifiers in URLs to be disabled. Off by default.
     *
     * @param disableUrlRewriting set to <tt>true</tt> to disable URL encoding methods in the response wrapper
     *                            and prevent the use of <tt>jsessionid</tt> parameters.
     */
    public void setDisableUrlRewriting(boolean disableUrlRewriting) {
        this.disableUrlRewriting = disableUrlRewriting;
    }

    /**
     * Allows the session attribute name to be customized for this repository instance.
     *
     * @param springSecurityContextKey the key under which the security context will be stored. Defaults to
     * {@link #SPRING_SECURITY_CONTEXT_KEY}.
     */
    public void setSpringSecurityContextKey(String springSecurityContextKey) {
        Assert.hasText(springSecurityContextKey, "springSecurityContextKey cannot be empty");
        this.springSecurityContextKey = springSecurityContextKey;
    }

    //~ Inner Classes ==================================================================================================

    private static class Servlet3SaveToSessionRequestWrapper extends HttpServletRequestWrapper {
        private final SaveContextOnUpdateOrErrorResponseWrapper response;

        public Servlet3SaveToSessionRequestWrapper(HttpServletRequest request,SaveContextOnUpdateOrErrorResponseWrapper response) {
            super(request);
            this.response = response;
        }

        @Override
        public AsyncContext startAsync() {
            response.disableSaveOnResponseCommitted();
            return super.startAsync();
        }

        @Override
        public AsyncContext startAsync(ServletRequest servletRequest,
                ServletResponse servletResponse) throws IllegalStateException {
            response.disableSaveOnResponseCommitted();
            return super.startAsync(servletRequest, servletResponse);
        }
    }

    /**
     * Wrapper that is applied to every request/response to update the <code>HttpSession<code> with
     * the <code>SecurityContext</code> when a <code>sendError()</code> or <code>sendRedirect</code>
     * happens. See SEC-398.
     * <p>
     * Stores the necessary state from the start of the request in order to make a decision about whether
     * the security context has changed before saving it.
     */
    final class SaveToSessionResponseWrapper extends SaveContextOnUpdateOrErrorResponseWrapper {

        private final HttpServletRequest request;
        private final boolean httpSessionExistedAtStartOfRequest;
        private final SecurityContext contextBeforeExecution;
        private final Authentication authBeforeExecution;

        /**
         * Takes the parameters required to call <code>saveContext()</code> successfully in
         * addition to the request and the response object we are wrapping.
         *
         * @param request the request object (used to obtain the session, if one exists).
         * @param httpSessionExistedAtStartOfRequest indicates whether there was a session in place before the
         *        filter chain executed. If this is true, and the session is found to be null, this indicates that it was
         *        invalidated during the request and a new session will now be created.
         * @param context the context before the filter chain executed.
         *        The context will only be stored if it or its contents changed during the request.
         */
        SaveToSessionResponseWrapper(HttpServletResponse response, HttpServletRequest request,
                                                      boolean httpSessionExistedAtStartOfRequest,
                                                      SecurityContext context) {
            super(response, disableUrlRewriting);
            this.request = request;
            this.httpSessionExistedAtStartOfRequest = httpSessionExistedAtStartOfRequest;
            this.contextBeforeExecution = context;
            this.authBeforeExecution = context.getAuthentication();
        }

        /**
         * Stores the supplied security context in the session (if available) and if it has changed since it was
         * set at the start of the request. If the AuthenticationTrustResolver identifies the current user as
         * anonymous, then the context will not be stored.
         *
         * @param context the context object obtained from the SecurityContextHolder after the request has
         *        been processed by the filter chain. SecurityContextHolder.getContext() cannot be used to obtain
         *        the context as it has already been cleared by the time this method is called.
         *
         */
        @Override
        protected void saveContext(SecurityContext context) {
            final Authentication authentication = context.getAuthentication();
            HttpSession httpSession = request.getSession(false);

            // See SEC-776
            if (authentication == null || trustResolver.isAnonymous(authentication)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("SecurityContext is empty or contents are anonymous - context will not be stored in HttpSession.");
                }

                if (httpSession != null && !contextObject.equals(contextBeforeExecution)) {
                    // SEC-1587 A non-anonymous context may still be in the session
                    // SEC-1735 remove if the contextBeforeExecution was not anonymous
                    httpSession.removeAttribute(springSecurityContextKey);
                }
                return;
            }

            if (httpSession == null) {
                httpSession = createNewSessionIfAllowed(context);
            }

            // If HttpSession exists, store current SecurityContext but only if it has
            // actually changed in this thread (see SEC-37, SEC-1307, SEC-1528)
            if (httpSession != null) {
                // We may have a new session, so check also whether the context attribute is set SEC-1561
                if (contextChanged(context) || httpSession.getAttribute(springSecurityContextKey) == null) {
                    httpSession.setAttribute(springSecurityContextKey, context);

                    if (logger.isDebugEnabled()) {
                        logger.debug("SecurityContext stored to HttpSession: '" + context + "'");
                    }
                }
            }
        }

        private boolean contextChanged(SecurityContext context) {
            return context != contextBeforeExecution || context.getAuthentication() != authBeforeExecution;
        }

        private HttpSession createNewSessionIfAllowed(SecurityContext context) {
            if (httpSessionExistedAtStartOfRequest) {
                if (logger.isDebugEnabled()) {
                    logger.debug("HttpSession is now null, but was not null at start of request; "
                            + "session was invalidated, so do not create a new session");
                }

                return null;
            }

            if (!allowSessionCreation) {
                if (logger.isDebugEnabled()) {
                    logger.debug("The HttpSession is currently null, and the "
                                    + HttpSessionSecurityContextRepository.class.getSimpleName()
                                    + " is prohibited from creating an HttpSession "
                                    + "(because the allowSessionCreation property is false) - SecurityContext thus not "
                                    + "stored for next request");
                }

                return null;
            }
            // Generate a HttpSession only if we need to

            if (contextObject.equals(context)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("HttpSession is null, but SecurityContext has not changed from default empty context: ' "
                            + context
                            + "'; not creating HttpSession or storing SecurityContext");
                }

                return null;
            }

            if (logger.isDebugEnabled()) {
                logger.debug("HttpSession being created as SecurityContext is non-default");
            }

            try {
                return request.getSession(true);
            } catch (IllegalStateException e) {
                // Response must already be committed, therefore can't create a new session
                logger.warn("Failed to create a session, as response has been committed. Unable to store" +
                        " SecurityContext.");
            }

            return null;
        }
    }

    /**
     * Sets the {@link AuthenticationTrustResolver} to be used. The default is
     * {@link AuthenticationTrustResolverImpl}.
     *
     * @param trustResolver
     *            the {@link AuthenticationTrustResolver} to use. Cannot be
     *            null.
     */
    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        Assert.notNull(trustResolver, "trustResolver cannot be null");
        this.trustResolver = trustResolver;
    }
}
