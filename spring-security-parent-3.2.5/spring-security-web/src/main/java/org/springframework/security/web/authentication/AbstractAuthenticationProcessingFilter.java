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

package org.springframework.security.web.authentication;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Abstract processor of browser-based HTTP-based authentication requests.
 * 
 * <p> 基于浏览器的基于HTTP的身份验证请求的抽象处理器。
 *
 * <h3>Authentication Process</h3>
 * 
 * <p> 认证过程
 *
 * <p> The filter requires that you set the <tt>authenticationManager</tt> property. An <tt>AuthenticationManager</tt> is
 * required to process the authentication request tokens created by implementing classes.
 * 
 * <p> 筛选器要求您设置authenticationManager属性。需要AuthenticationManager来处理通过实现类创建的身份验证请求令牌。
 * 
 * <p>
 * This filter will intercept a request and attempt to perform authentication from that request if
 * the request matches the {@link #setRequiresAuthenticationRequestMatcher(RequestMatcher)}.
 * 
 * <p> 如果请求与setRequiresAuthenticationRequestMatcher（RequestMatcher）匹配，则此筛选器将拦截请求并尝试从该请求执行身份验证。
 * 
 * <p>
 * Authentication is performed by the {@link #attemptAuthentication(HttpServletRequest, HttpServletResponse)
 * attemptAuthentication} method, which must be implemented by subclasses.
 * 
 * <p> 身份验证由tryAuthentication方法执行，该方法必须由子类实现。
 *
 * <h4>Authentication Success</h4>
 * 
 * <p> 认证成功
 * 
 * <p> If authentication is successful, the resulting {@link Authentication} object will be placed into the
 * <code>SecurityContext</code> for the current thread, which is guaranteed to have already been created by an earlier
 * filter.
 * 
 * <p> 如果身份验证成功，则将生成的Authentication对象放置在当前线程的SecurityContext中，这保证已由较早的过滤器创建。
 * 
 * <p>
 * The configured {@link #setAuthenticationSuccessHandler(AuthenticationSuccessHandler) AuthenticationSuccessHandler} will
 * then be called to take the redirect to the appropriate destination after a successful login. The default behaviour
 * is implemented in a {@link SavedRequestAwareAuthenticationSuccessHandler} which will make use of any
 * <tt>DefaultSavedRequest</tt> set by the <tt>ExceptionTranslationFilter</tt> and redirect the user to the URL contained
 * therein. Otherwise it will redirect to the webapp root "/". You can customize this behaviour by injecting a
 * differently configured instance of this class, or by using a different implementation.
 * 
 * <p> 成功登录后，将调用已配置的AuthenticationSuccessHandler，以将重定向到适当的目的地。
 * 默认行为在SavedRequestAwareAuthenticationSuccessHandler中实现，
 * 它将使用ExceptionTranslationFilter设置的任何DefaultSavedRequest并将用户重定向到其中包含的URL。否则，
 * 它将重定向到Web应用程序根目录“ /”。您可以通过注入此类的不同配置实例或使用其他实现来自定义此行为。
 * 
 * <p>
 * See the {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, Authentication)
 * successfulAuthentication} method for more information.
 * 
 * <p> 有关更多信息，请参见成功的身份验证方法。
 *
 * <h4>Authentication Failure</h4>
 * 
 * <p> 验证失败
 *
 * <p> If authentication fails, it will delegate to the configured {@link AuthenticationFailureHandler} to allow the
 * failure information to be conveyed to the client. The default implementation is
 * {@link SimpleUrlAuthenticationFailureHandler}, which sends a 401 error code to the client. It may also be configured
 * with a failure URL as an alternative. Again you can inject whatever behaviour you require here.
 *
 * <p> 如果认证失败，它将委派给已配置的AuthenticationFailureHandler，以允许将失败信息传达给客户端。默认实现是
 * SimpleUrlAuthenticationFailureHandler，它向客户端发送401错误代码。也可以用失败URL进行配置。同样，您可以在此处注入所需的任何行为。
 * 
 * <h4>Event Publication</h4>
 * 
 * <p> 活动发布
 *
 * <p> If authentication is successful, an {@link InteractiveAuthenticationSuccessEvent} will be published via the
 * application context. No events will be published if authentication was unsuccessful, because this would generally be
 * recorded via an {@code AuthenticationManager}-specific application event.
 * 
 * <p> 如果身份验证成功，则将通过应用程序上下文发布InteractiveAuthenticationSuccessEvent。如果身份验证失败，
 * 则不会发布任何事件，因为通常会通过AuthenticationManager特定的应用程序事件来记录该事件。
 *
 * <h4>Session Authentication</h4>
 * 
 * <p> 会话认证
 *
 * <p> The class has an optional {@link SessionAuthenticationStrategy} which will be invoked immediately after a
 * successful call to {@code attemptAuthentication()}. Different implementations
 * {@link #setSessionAuthenticationStrategy(SessionAuthenticationStrategy) can be injected} to enable things like
 * session-fixation attack prevention or to control the number of simultaneous sessions a principal may have.
 *
 * <p> 该类具有可选的SessionAuthenticationStrategy，将在成功调用tryAuthentication（）之后立即调用它。可以注入不同的实现，
 * 以实现诸如防止会话固定攻击之类的功能，或控制主体可能同时进行的会话数。
 * 
 * @author Ben Alex
 * @author Luke Taylor
 */
public abstract class AbstractAuthenticationProcessingFilter extends GenericFilterBean implements
        ApplicationEventPublisherAware, MessageSourceAware {
    //~ Static fields/initializers =====================================================================================

    /**
     * @deprecated Use the value in {@link WebAttributes} directly.
     */
    @Deprecated
    public static final String SPRING_SECURITY_LAST_EXCEPTION_KEY = WebAttributes.AUTHENTICATION_EXCEPTION;

    //~ Instance fields ================================================================================================

    protected ApplicationEventPublisher eventPublisher;
    protected AuthenticationDetailsSource<HttpServletRequest,?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private AuthenticationManager authenticationManager;
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private RememberMeServices rememberMeServices = new NullRememberMeServices();

    private RequestMatcher requiresAuthenticationRequestMatcher;

    /**
     * The URL destination that this filter intercepts and processes (usually
     * something like <code>/j_spring_security_check</code>)
     * 
     * <p> 该过滤器拦截和处理的URL目标（通常是/ j_spring_security_check之类的东西）
     * 
     * @deprecated use {@link #requiresAuthenticationRequestMatcher} instead
     */
    @Deprecated
    private String filterProcessesUrl;

    private boolean continueChainBeforeSuccessfulAuthentication = false;

    private SessionAuthenticationStrategy sessionStrategy = new NullAuthenticatedSessionStrategy();

    private boolean allowSessionCreation = true;

    private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    private AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();

    //~ Constructors ===================================================================================================

    /**
     * @param defaultFilterProcessesUrl the default value for <tt>filterProcessesUrl</tt>.
     * 
     * <p> filterProcessesUrl的默认值。
     */
    protected AbstractAuthenticationProcessingFilter(String defaultFilterProcessesUrl) {
        this.requiresAuthenticationRequestMatcher = new FilterProcessUrlRequestMatcher(defaultFilterProcessesUrl);
        this.filterProcessesUrl = defaultFilterProcessesUrl;
    }

    /**
     * Creates a new instance
     *
     * @param requiresAuthenticationRequestMatcher
     *            the {@link RequestMatcher} used to determine if authentication
     *            is required. Cannot be null.
     *            
     * <p> 用于确定是否需要身份验证的RequestMatcher。 不能为null。
     */
    protected AbstractAuthenticationProcessingFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        Assert.notNull(requiresAuthenticationRequestMatcher, "requiresAuthenticationRequestMatcher cannot be null");
        this.requiresAuthenticationRequestMatcher = requiresAuthenticationRequestMatcher;
    }

    //~ Methods ========================================================================================================

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(authenticationManager, "authenticationManager must be specified");

        if (rememberMeServices == null) {
            rememberMeServices = new NullRememberMeServices();
        }
    }

    /**
     * Invokes the {@link #requiresAuthentication(HttpServletRequest, HttpServletResponse) requiresAuthentication}
     * method to determine whether the request is for authentication and should be handled by this filter.
     * If it is an authentication request, the
     * {@link #attemptAuthentication(HttpServletRequest, HttpServletResponse) attemptAuthentication} will be invoked
     * to perform the authentication. There are then three possible outcomes:
     * 
     * <p> 调用requireAuthentication方法，以确定请求是否用于身份验证，是否应由此过滤器处理。如果是身份验证请求，
     * 将调用tryAuthentication来执行身份验证。然后有三种可能的结果：
     * 
     * <ol>
     * <li>An <tt>Authentication</tt> object is returned.
     * The configured {@link SessionAuthenticationStrategy} will be invoked (to handle any session-related behaviour
     * such as creating a new session to protect against session-fixation attacks) followed by the invocation of
     * {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, Authentication)
     * successfulAuthentication} method</li>
     * 
     * <p> 返回认证对象。将调用配置的SessionAuthenticationStrategy
     * （以处理任何与会话相关的行为，例如创建新会话以防止会话固定攻击），然后调用成功的身份验证方法
     * 
     * <li>An <tt>AuthenticationException</tt> occurs during authentication.
     * The {@link #unsuccessfulAuthentication(HttpServletRequest, HttpServletResponse, AuthenticationException)
     * unsuccessfulAuthentication} method will be invoked</li>
     * 
     * <p> 身份验证期间发生AuthenticationException。将调用unsuccessfulAuthentication方法
     *  
     * <li>Null is returned, indicating that the authentication process is incomplete.
     * The method will then return immediately, assuming that the subclass has done any necessary work (such as
     * redirects) to continue the authentication process. The assumption is that a later request will be received
     * by this method where the returned <tt>Authentication</tt> object is not null.
     * 
     * <p> 返回Null，表示认证过程不完整。然后，该方法将立即返回，并假定子类已完成任何必要的工作（例如重定向）以继续进行身份验证过程。
     * 假定在返回的Authentication对象不为null的情况下，此方法将接收更高的请求。
     * 
     * </ol>
     */
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (!requiresAuthentication(request, response)) {
            chain.doFilter(request, response);

            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Request is to process authentication");
        }

        Authentication authResult;

        try {
            authResult = attemptAuthentication(request, response);
            if (authResult == null) {
                // return immediately as subclass has indicated that it hasn't completed authentication
            	
            	// 立即返回，因为子类表明它尚未完成认证
                return;
            }
            sessionStrategy.onAuthentication(authResult, request, response);
        } catch(InternalAuthenticationServiceException failed) {
            logger.error("An internal error occurred while trying to authenticate the user.", failed);
            unsuccessfulAuthentication(request, response, failed);

            return;
        }
        catch (AuthenticationException failed) {
            // Authentication failed
            unsuccessfulAuthentication(request, response, failed);

            return;
        }

        // Authentication success
        if (continueChainBeforeSuccessfulAuthentication) {
            chain.doFilter(request, response);
        }

        successfulAuthentication(request, response, chain, authResult);
    }

    /**
     * Indicates whether this filter should attempt to process a login request for the current invocation.
     * 
     * <p> 指示此过滤器是否应尝试处理当前调用的登录请求。
     * 
     * <p>
     * It strips any parameters from the "path" section of the request URL (such
     * as the jsessionid parameter in
     * <em>http://host/myapp/index.html;jsessionid=blah</em>) before matching
     * against the <code>filterProcessesUrl</code> property.
     * 
     * <p>在与filterProcessesUrl属性匹配之前，它将剥离请求URL的“路径”部分中的所有参数
     * （例如http：//host/myapp/index.html; jsessionid = blah中的jsessionid参数）。
     * 
     * <p>
     * Subclasses may override for special requirements, such as Tapestry integration.
     * 
     * <p> 子类可能针对特殊要求而被覆盖，例如Tapestry集成
     *
     * @return <code>true</code> if the filter should attempt authentication, <code>false</code> otherwise.
     * 
     * <p> 如果过滤器应尝试进行身份验证，则为true，否则为false。
     * 
     * @deprecated use {@link #setRequiresAuthenticationRequestMatcher(RequestMatcher)} instead
     */
    @Deprecated
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        return requiresAuthenticationRequestMatcher.matches(request);
    }

    /**
     * Performs actual authentication.
     * 
     * <p> 执行实际身份验证。
     * <p>
     * The implementation should do one of the following:
     * 
     * <p> 该实现应执行以下操作之一：
     * 
     * <ol>
     * <li>Return a populated authentication token for the authenticated user, indicating successful authentication</li>
     * 
     * <p> 返回已填充身份验证用户的身份验证令牌，表示身份验证成功
     * 
     * <li>Return null, indicating that the authentication process is still in progress. Before returning, the
     * implementation should perform any additional work required to complete the process.</li>
     * 
     * <p> 返回null，表示身份验证过程仍在进行中。 在返回之前，实现应执行完成该过程所需的任何其他工作。
     * 
     * <li>Throw an <tt>AuthenticationException</tt> if the authentication process fails</li>
     * 
     * <p> 如果身份验证过程失败，则引发AuthenticationException
     * 
     * </ol>
     *
     * @param request   from which to extract parameters and perform the authentication
     * 
     * <p> 
     * 
     * @param response  the response, which may be needed if the implementation has to do a redirect as part of a
     *                  multi-stage authentication process (such as OpenID).
     * 
     * <p> 从中提取参数并执行身份验证
     * 
     * @return the authenticated user token, or null if authentication is incomplete.
     * 
     * <p> 经过身份验证的用户令牌；如果身份验证不完整，则返回null。
     *
     * @throws AuthenticationException if authentication fails.
     * 
     * <p> 如果身份验证失败。
     */
    public abstract Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException;

    /**
     * Default behaviour for successful authentication.
     * 
     * <p> 成功认证的默认行为
     * 
     * <ol>
     * <li>Sets the successful <tt>Authentication</tt> object on the {@link SecurityContextHolder}</li>
     * 
     * <p> 在SecurityContextHolder上设置成功的身份验证对象
     * 
     * <li>Informs the configured <tt>RememberMeServices</tt> of the successful login</li>
     * 
     * <p> 通知已配置的RememberMeServices成功登录
     * 
     * <li>Fires an {@link InteractiveAuthenticationSuccessEvent} via the configured
     * <tt>ApplicationEventPublisher</tt></li>
     * 
     * <p> 通过配置的ApplicationEventPublisher触发InteractiveAuthenticationSuccessEvent
     * 
     * <li>Delegates additional behaviour to the {@link AuthenticationSuccessHandler}.</li>
     * 
     * <p> 将其他行为委托给AuthenticationSuccessHandler。
     * 
     * </ol>
     *
     * <p> Subclasses can override this method to continue the {@link FilterChain} after successful authentication.
     * 
     * <p> 子类可以重写此方法，以在成功身份验证后继续FilterChain。
     * @param request
     * @param response
     * @param chain
     * @param authResult the object returned from the <tt>attemptAuthentication</tt> method.
     * 
     * <p> 从tryAuthentication方法返回的对象。
     * 
     * @throws IOException
     * @throws ServletException
     */
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException{
        successfulAuthentication(request, response, authResult);
    }

    /**
     * Default behaviour for successful authentication.
     * <ol>
     * <li>Sets the successful <tt>Authentication</tt> object on the {@link SecurityContextHolder}</li>
     * <li>Informs the configured <tt>RememberMeServices</tt> of the successful login</li>
     * <li>Fires an {@link InteractiveAuthenticationSuccessEvent} via the configured
     * <tt>ApplicationEventPublisher</tt></li>
     * <li>Delegates additional behaviour to the {@link AuthenticationSuccessHandler}.</li>
     * </ol>
     *
     * @param authResult the object returned from the <tt>attemptAuthentication</tt> method.
     * @deprecated since 3.1. Use {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, FilterChain, Authentication)} instead.
     */
    @Deprecated
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            Authentication authResult) throws IOException, ServletException {

        if (logger.isDebugEnabled()) {
            logger.debug("Authentication success. Updating SecurityContextHolder to contain: " + authResult);
        }

        SecurityContextHolder.getContext().setAuthentication(authResult);

        rememberMeServices.loginSuccess(request, response, authResult);

        // Fire event
        if (this.eventPublisher != null) {
            eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
        }

        successHandler.onAuthenticationSuccess(request, response, authResult);
    }

    /**
     * Default behaviour for unsuccessful authentication.
     * 
     * <p> 身份验证失败的默认行为。
     * 
     * <ol>
     * <li>Clears the {@link SecurityContextHolder}</li>
     * 
     * <p> 清除SecurityContextHolder
     * 
     * <li>Stores the exception in the session (if it exists or <tt>allowSesssionCreation</tt> is set to <tt>true</tt>)</li>
     * 
     * <p> 将异常存储在会话中（如果存在或将allowSesssionCreation设置为true）
     * 
     * <li>Informs the configured <tt>RememberMeServices</tt> of the failed login</li>
     * 
     * <p> 通知配置的RememberMeServices登录失败
     * 
     * <li>Delegates additional behaviour to the {@link AuthenticationFailureHandler}.</li>
     * 
     * <p> 将其他行为委托给AuthenticationFailureHandler。
     * 
     * </ol>
     */
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.clearContext();

        if (logger.isDebugEnabled()) {
            logger.debug("Authentication request failed: " + failed.toString());
            logger.debug("Updated SecurityContextHolder to contain null Authentication");
            logger.debug("Delegating to authentication failure handler " + failureHandler);
        }

        rememberMeServices.loginFail(request, response);

        failureHandler.onAuthenticationFailure(request, response, failed);
    }

    protected AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Deprecated
    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }

    /**
     * Sets the URL that determines if authentication is required
     * 
     * <p> 设置确定是否需要身份验证的URL
     *
     * @param filterProcessesUrl
     * @deprecated use {@link #setRequiresAuthenticationRequestMatcher(RequestMatcher)} instead
     */
    @Deprecated
    public void setFilterProcessesUrl(String filterProcessesUrl) {
        this.requiresAuthenticationRequestMatcher = new FilterProcessUrlRequestMatcher(filterProcessesUrl);
        this.filterProcessesUrl = filterProcessesUrl;
    }

    public final void setRequiresAuthenticationRequestMatcher(RequestMatcher requestMatcher) {
        Assert.notNull(requestMatcher, "requestMatcher cannot be null");
        this.filterProcessesUrl = null;
        this.requiresAuthenticationRequestMatcher = requestMatcher;
    }

    public RememberMeServices getRememberMeServices() {
        return rememberMeServices;
    }

    public void setRememberMeServices(RememberMeServices rememberMeServices) {
        Assert.notNull("rememberMeServices cannot be null");
        this.rememberMeServices = rememberMeServices;
    }

    /**
     * Indicates if the filter chain should be continued prior to delegation to
     * {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse,
     * Authentication)}, which may be useful in certain environment (such as
     * Tapestry applications). Defaults to <code>false</code>.
     * 
     * <p> 指示在委托给成功的身份验证（HttpServletRequest，HttpServletResponse，Authentication）
     * 之前是否应继续执行过滤器链，这在某些环境（例如Tapestry应用程序）中可能很有用。 默认为false。
     * 
     */
    public void setContinueChainBeforeSuccessfulAuthentication(boolean continueChainBeforeSuccessfulAuthentication) {
        this.continueChainBeforeSuccessfulAuthentication = continueChainBeforeSuccessfulAuthentication;
    }

    public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest,?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    protected boolean getAllowSessionCreation() {
        return allowSessionCreation;
    }

    public void setAllowSessionCreation(boolean allowSessionCreation) {
        this.allowSessionCreation = allowSessionCreation;
    }

    /**
     * The session handling strategy which will be invoked immediately after an authentication request is
     * successfully processed by the <tt>AuthenticationManager</tt>. Used, for example, to handle changing of the
     * session identifier to prevent session fixation attacks.
     * 
     * <p> AuthenticationManager成功处理身份验证请求后将立即调用的会话处理策略。 例如，用于处理会话标识符的更改以防止会话固定攻击。
     *
     * @param sessionStrategy the implementation to use. If not set a null implementation is
     * used.
     * 
     * <p> 使用的实现。 如果未设置，则使用null实现。
     */
    public void setSessionAuthenticationStrategy(SessionAuthenticationStrategy sessionStrategy) {
        this.sessionStrategy = sessionStrategy;
    }

    /**
     * Sets the strategy used to handle a successful authentication.
     * By default a {@link SavedRequestAwareAuthenticationSuccessHandler} is used.
     * 
     * <p> 设置用于处理成功身份验证的策略。 默认情况下，使用SavedRequestAwareAuthenticationSuccessHandler。
     */
    public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler successHandler) {
        Assert.notNull(successHandler, "successHandler cannot be null");
        this.successHandler = successHandler;
    }

    public void setAuthenticationFailureHandler(AuthenticationFailureHandler failureHandler) {
        Assert.notNull(failureHandler, "failureHandler cannot be null");
        this.failureHandler = failureHandler;
    }

    protected AuthenticationSuccessHandler getSuccessHandler() {
        return successHandler;
    }

    protected AuthenticationFailureHandler getFailureHandler() {
        return failureHandler;
    }

    private static final class FilterProcessUrlRequestMatcher implements RequestMatcher {
        private final String filterProcessesUrl;

        private FilterProcessUrlRequestMatcher(String filterProcessesUrl) {
            Assert.hasLength(filterProcessesUrl, "filterProcessesUrl must be specified");
            Assert.isTrue(UrlUtils.isValidRedirectUrl(filterProcessesUrl), filterProcessesUrl + " isn't a valid redirect URL");
            this.filterProcessesUrl = filterProcessesUrl;
        }

        public boolean matches(HttpServletRequest request) {
            String uri = request.getRequestURI();
            int pathParamIndex = uri.indexOf(';');

            if (pathParamIndex > 0) {
                // strip everything after the first semi-colon
            	// 在第一个分号后删除所有内容
                uri = uri.substring(0, pathParamIndex);
            }

            if ("".equals(request.getContextPath())) {
                return uri.endsWith(filterProcessesUrl);
            }

            return uri.endsWith(request.getContextPath() + filterProcessesUrl);
        }
    }
}
