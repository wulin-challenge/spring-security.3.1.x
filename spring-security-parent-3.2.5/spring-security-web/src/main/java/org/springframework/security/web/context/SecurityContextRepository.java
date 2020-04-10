package org.springframework.security.web.context;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;

/**
 * Strategy used for persisting a {@link SecurityContext} between requests.
 * 
 * <p> 用于在请求之间保留SecurityContext的策略。
 * 
 * <p>
 * Used by {@link SecurityContextPersistenceFilter} to obtain the context which should be used for the current thread
 * of execution and to store the context once it has been removed from thread-local storage and the request has
 * completed.
 * 
 * <p> 由SecurityContextPersistenceFilter用来获取应用于当前执行线程的上下文，
 * 并在从线程本地存储中删除该上下文且请求完成后存储该上下文。
 * 
 * <p>
 * The persistence mechanism used will depend on the implementation, but most commonly the <tt>HttpSession</tt> will
 * be used to store the context.
 * 
 * <p> 使用的持久性机制将取决于实现，但是最常见的是，将使用HttpSession来存储上下文。
 *
 * @author Luke Taylor
 * @since 3.0
 *
 * @see SecurityContextPersistenceFilter
 * @see HttpSessionSecurityContextRepository
 * @see SaveContextOnUpdateOrErrorResponseWrapper
 */
public interface SecurityContextRepository {

    /**
     * Obtains the security context for the supplied request. For an unauthenticated user, an empty context
     * implementation should be returned. This method should not return null.
     * 
     * <p> 获取所提供请求的安全上下文。 对于未经身份验证的用户，应返回一个空的上下文实现。 此方法不应返回null。
     * 
     * <p>
     * The use of the <tt>HttpRequestResponseHolder</tt> parameter allows implementations to return wrapped versions of
     * the request or response (or both), allowing them to access implementation-specific state for the request.
     * The values obtained from the holder will be passed on to the filter chain and also to the <tt>saveContext</tt>
     * method when it is finally called. Implementations may wish to return a subclass of
     * {@link SaveContextOnUpdateOrErrorResponseWrapper} as the response object, which guarantees that the context is
     * persisted when an error or redirect occurs.
     * 
     * <p> HttpRequestResponseHolder参数的使用允许实现返回请求或响应（或两者）的包装版本，从而允许它们访问请求的特定于实现的状态。 
     * 当最终调用该方法时，将从持有人获得的值传递到过滤器链以及saveContext方法。 实现可能希望返回
     * SaveContextOnUpdateOrErrorResponseWrapper的子类作为响应对象，以保证在发生错误或重定向时上下文保持不变。
     *
     * @param requestResponseHolder holder for the current request and response for which the context should be loaded.
     * 
     * <p> 当前请求和响应的持有者，应为其加载上下文。
     *
     * @return The security context which should be used for the current request, never null.
     * 
     * <p> 当前请求应使用的安全上下文，决不能为null。
     */
    SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder);

    /**
     * Stores the security context on completion of a request.
     * 
     * <p> 在请求完成时存储安全上下文。
     *
     * @param context the non-null context which was obtained from the holder.
     * 
     * <p> 从持有人获得的非null上下文。
     * 
     * @param request
     * @param response
     */
    void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response);

    /**
     * Allows the repository to be queried as to whether it contains a security context for the
     * current request.
     * 
     * <p> 允许查询存储库是否包含当前请求的安全上下文。
     *
     * @param request the current request - 当前请求
     * @return true if a context is found for the request, false otherwise
     * 
     * <p>对于这个请求如何一个上下文被找到，则为true，否则为false
     */
    boolean containsContext(HttpServletRequest request);
}
