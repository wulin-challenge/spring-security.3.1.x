package org.springframework.security.web.authentication;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Base class containing the logic used by strategies which handle redirection to a URL and
 * are passed an {@code Authentication} object as part of the contract.
 * See {@link AuthenticationSuccessHandler} and
 * {@link org.springframework.security.web.authentication.logout.LogoutSuccessHandler LogoutSuccessHandler}, for example.
 * 
 * <p> 基类，包含策略所使用的逻辑，这些策略用于处理重定向到URL并作为协定的一部分传递给Authentication对象。例如，
 * 请参阅AuthenticationSuccessHandler和LogoutSuccessHandler。
 * 
 * <p>
 * Uses the following logic sequence to determine how it should handle the forward/redirect
 * 
 * <p> 使用以下逻辑序列来确定应如何处理转发/重定向
 * 
 * <ul>
 * <li>
 * If the {@code alwaysUseDefaultTargetUrl} property is set to true, the {@code defaultTargetUrl} property
 * will be used for the destination.
 * </li>
 * 
 * <p> 如果alwaysUseDefaultTargetUrl属性设置为true，则defaultTargetUrl属性将用于目标。
 * 
 * <li>
 * If a parameter matching the value of {@code targetUrlParameter} has been set on the request, the value will be used
 * as the destination. If you are enabling this functionality, then you should ensure that the parameter
 * cannot be used by an attacker to redirect the user to a malicious site (by clicking on a URL with the parameter
 * included, for example). Typically it would be used when the parameter is included in the login form and submitted with
 * the username and password.
 * </li>
 * 
 * <p> 如果在请求上设置了与targetUrlParameter值匹配的参数，则该值将用作目标。如果启用此功能，则应确保攻击者无法使用该参数将用户重定向到恶意站点（例如，通过单击包含该参数的URL）。
 * 通常，当参数包含在登录表单中并与用户名和密码一起提交时，将使用该参数。
 * 
 * <li>
 * If the {@code useReferer} property is set, the "Referer" HTTP header value will be used, if present.
 * </li>
 * 
 * <p> 如果设置了useReferer属性，则将使用“ Referer” HTTP标头值（如果存在）。
 * 
 * <li>
 * As a fallback option, the {@code defaultTargetUrl} value will be used.
 * </li>
 * 
 * <p> 作为后备选项，将使用defaultTargetUrl值。
 * </ul>
 *
 * @author Luke Taylor
 * @since 3.0
 */
public abstract class AbstractAuthenticationTargetUrlRequestHandler {

    protected final Log logger = LogFactory.getLog(this.getClass());
    private String targetUrlParameter = null;
    private String defaultTargetUrl = "/";
    private boolean alwaysUseDefaultTargetUrl = false;
    private boolean useReferer = false;
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    protected AbstractAuthenticationTargetUrlRequestHandler() {
    }

    /**
     * Invokes the configured {@code RedirectStrategy} with the URL returned by the {@code determineTargetUrl} method.
     * 
     * <p> 使用由defineTargetUrl方法返回的URL调用配置的RedirectStrategy。
     * 
     * <p>
     * The redirect will not be performed if the response has already been committed.
     * 
     * <p> 如果响应已经提交，将不会执行重定向。
     */
    protected void handle(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        redirectStrategy.sendRedirect(request, response, targetUrl);
    }

    /**
     * Builds the target URL according to the logic defined in the main class Javadoc.
     * 
     * <p> 根据主类Javadoc中定义的逻辑构建目标URL。
     */
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        if (isAlwaysUseDefaultTargetUrl()) {
            return defaultTargetUrl;
        }

        // Check for the parameter and use that if available
        // 检查参数并使用（如果可用）
        String targetUrl = null;

        if (targetUrlParameter != null  ) {
            targetUrl = request.getParameter(targetUrlParameter);

            if (StringUtils.hasText(targetUrl)) {
                logger.debug("Found targetUrlParameter in request: " + targetUrl);

                return targetUrl;
            }
        }

        if (useReferer && !StringUtils.hasLength(targetUrl)) {
            targetUrl = request.getHeader("Referer");
            logger.debug("Using Referer header: " + targetUrl);
        }

        if (!StringUtils.hasText(targetUrl)) {
            targetUrl = defaultTargetUrl;
            logger.debug("Using default Url: " + targetUrl);
        }

        return targetUrl;
    }

    /**
     * Supplies the default target Url that will be used if no saved request is found or the
     * {@code alwaysUseDefaultTargetUrl} property is set to true. If not set, defaults to {@code /}.
     * 
     * <p> 提供默认的目标Url，如果找不到保存的请求或alwaysUseDefaultTargetUrl属性设置为true，将使用该默认目标。 如果未设置，则默认为/。
     *
     * @return the defaultTargetUrl property
     */
    protected final String getDefaultTargetUrl() {
        return defaultTargetUrl;
    }

    /**
     * Supplies the default target Url that will be used if no saved request is found in the session, or the
     * {@code alwaysUseDefaultTargetUrl} property is set to true. If not set, defaults to {@code /}. It
     * will be treated as relative to the web-app's context path, and should include the leading <code>/</code>.
     * Alternatively, inclusion of a scheme name (such as "http://" or "https://") as the prefix will denote a
     * fully-qualified URL and this is also supported.
     * 
     * <p> 提供默认的目标Url，如果在会话中未找到已保存的请求，或者alwaysUseDefaultTargetUrl属性设置为true，则将使用该默认目标。 如果未设置，则默认为/。 
     * 它将被视为相对于Web应用程序的上下文路径，并且应包含前导/。 或者，包含方案名称（例如“ http：//”或“ https：//”）
     * 作为前缀将表示完全限定的URL，并且也支持此名称。
     *
     * @param defaultTargetUrl
     */
    public void setDefaultTargetUrl(String defaultTargetUrl) {
        Assert.isTrue(UrlUtils.isValidRedirectUrl(defaultTargetUrl),
                "defaultTarget must start with '/' or with 'http(s)'");
        this.defaultTargetUrl = defaultTargetUrl;
    }

    /**
     * If <code>true</code>, will always redirect to the value of {@code defaultTargetUrl}
     * (defaults to <code>false</code>).
     * 
     * <p> 如果为true，将始终重定向到defaultTargetUrl的值（默认为false）。
     */
    public void setAlwaysUseDefaultTargetUrl(boolean alwaysUseDefaultTargetUrl) {
        this.alwaysUseDefaultTargetUrl = alwaysUseDefaultTargetUrl;
    }

    protected boolean isAlwaysUseDefaultTargetUrl() {
        return alwaysUseDefaultTargetUrl;
    }

    /**
     * If this property is set, the current request will be checked for this a parameter with this name
     * and the value used as the target URL if present.
     * 
     * <p> 如果设置了此属性，将使用当前名称的参数检查该请求，并使用该名称和值作为目标URL（如果存在）。
     *
     * @param targetUrlParameter the name of the parameter containing the encoded target URL. Defaults
     * to null.
     * 
     * <p> 包含已编码目标URL的参数的名称。 默认为空。
     */
    public void setTargetUrlParameter(String targetUrlParameter) {
        if(targetUrlParameter != null) {
            Assert.hasText(targetUrlParameter,"targetUrlParameter cannot be empty");
        }
        this.targetUrlParameter = targetUrlParameter;
    }

    protected String getTargetUrlParameter() {
        return targetUrlParameter;
    }

    /**
     * Allows overriding of the behaviour when redirecting to a target URL.
     * 
     * <p> 重定向到目标URL时，允许覆盖行为。
     */
    public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
        this.redirectStrategy = redirectStrategy;
    }

    protected RedirectStrategy getRedirectStrategy() {
        return redirectStrategy;
    }

    /**
     * If set to {@code true} the {@code Referer} header will be used (if available). Defaults to {@code false}.
     * 
     * <p> 如果设置为true，则将使用Referer标头（如果可用）。 默认为false。
     */
    public void setUseReferer(boolean useReferer) {
        this.useReferer = useReferer;
    }

}
