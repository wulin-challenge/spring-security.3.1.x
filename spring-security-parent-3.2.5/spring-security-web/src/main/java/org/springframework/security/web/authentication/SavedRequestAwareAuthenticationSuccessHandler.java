package org.springframework.security.web.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.util.StringUtils;

/**
 * An authentication success strategy which can make use of the {@link DefaultSavedRequest} which may have been stored in
 * the session by the {@link ExceptionTranslationFilter}. When such a request is intercepted and requires authentication,
 * the request data is stored to record the original destination before the authentication process commenced, and to
 * allow the request to be reconstructed when a redirect to the same URL occurs. This class is responsible for
 * performing the redirect to the original URL if appropriate.
 * 
 * <p> 可以使用ExceptionTranslationFilter可能已存储在会话中的DefaultSavedRequest的身份验证成功策略。
 * 当此类请求被拦截并需要进行身份验证时，将存储请求数据以记录身份验证过程开始之前的原始目的地，并允许在重定向到相同URL时重构请求。
 * 如果合适，此类负责执行重定向到原始URL的操作。
 * 
 * <p>
 * Following a successful authentication, it decides on the redirect destination, based on the following scenarios:
 * 
 * <p> 成功进行身份验证后，它将根据以下情况决定重定向目标：
 * 
 * <ul>
 * <li>
 * If the {@code alwaysUseDefaultTargetUrl} property is set to true, the {@code defaultTargetUrl}
 * will be used for the destination. Any {@code DefaultSavedRequest} stored in the session will be
 * removed.
 * </li>
 * 
 * <p> 如果alwaysUseDefaultTargetUrl属性设置为true，则将defaultTargetUrl用于目标。会话中存储的所有DefaultSavedRequest将被删除。
 * 
 * <li>
 * If the {@code targetUrlParameter} has been set on the request, the value will be used as the destination.
 * Any {@code DefaultSavedRequest} will again be removed.
 * </li>
 * 
 * <p> 如果已在请求上设置了targetUrlParameter，则该值将用作目标。任何DefaultSavedRequest将再次被删除。
 * 
 * <li>
 * If a {@link SavedRequest} is found in the {@code RequestCache} (as set by the {@link ExceptionTranslationFilter} to
 * record the original destination before the authentication process commenced), a redirect will be performed to the
 * Url of that original destination. The {@code SavedRequest} object will remain cached and be picked up
 * when the redirected request is received
 * (See {@link org.springframework.security.web.savedrequest.SavedRequestAwareWrapper SavedRequestAwareWrapper}).
 * </li>
 * 
 * <p> 如果在RequestCache中找到SavedRequest（由ExceptionTranslationFilter设置为在身份验证过程开始之前记录原始目标），则将重定向到该原始目标的Url。
 * 当收到重定向的请求时，SavedRequest对象将保持高速缓存并被拾取（请参阅SavedRequestAwareWrapper）。
 * 
 * <li>
 * If no {@code SavedRequest} is found, it will delegate to the base class.
 * </li>
 * 
 * <p> 如果未找到SavedRequest，它将委派给基类。
 * </ul>
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class SavedRequestAwareAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    protected final Log logger = LogFactory.getLog(this.getClass());

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws ServletException, IOException {
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if (savedRequest == null) {
            super.onAuthenticationSuccess(request, response, authentication);

            return;
        }
        String targetUrlParameter = getTargetUrlParameter();
        if (isAlwaysUseDefaultTargetUrl() || (targetUrlParameter != null && StringUtils.hasText(request.getParameter(targetUrlParameter)))) {
            requestCache.removeRequest(request, response);
            super.onAuthenticationSuccess(request, response, authentication);

            return;
        }

        clearAuthenticationAttributes(request);

        // Use the DefaultSavedRequest URL
        String targetUrl = savedRequest.getRedirectUrl();
        logger.debug("Redirecting to DefaultSavedRequest Url: " + targetUrl);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    public void setRequestCache(RequestCache requestCache) {
        this.requestCache = requestCache;
    }
}
