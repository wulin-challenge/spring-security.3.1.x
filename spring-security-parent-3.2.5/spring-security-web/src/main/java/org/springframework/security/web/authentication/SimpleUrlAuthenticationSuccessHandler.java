package org.springframework.security.web.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.WebAttributes;

/**
 * <tt>AuthenticationSuccessHandler</tt> which can be configured with a default URL which users should be
 * sent to upon successful authentication.
 * 
 * <p> 可以使用默认URL配置AuthenticationSuccessHandler，成功身份验证后应将默认URL发送给用户。
 * 
 * <p>
 * The logic used is that of the {@link AbstractAuthenticationTargetUrlRequestHandler parent class}.
 * 
 * <p> 使用的逻辑是父类的逻辑。
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class SimpleUrlAuthenticationSuccessHandler extends AbstractAuthenticationTargetUrlRequestHandler implements AuthenticationSuccessHandler {

    public SimpleUrlAuthenticationSuccessHandler() {
    }

    /**
     * Constructor which sets the <tt>defaultTargetUrl</tt> property of the base class.
     * 
     * <p> 构造函数，用于设置基类的defaultTargetUrl属性。
     * 
     * @param defaultTargetUrl the URL to which the user should be redirected on successful authentication.
     * 
     * <p> 成功验证后应将用户重定向到的URL。
     */
    public SimpleUrlAuthenticationSuccessHandler(String defaultTargetUrl) {
        setDefaultTargetUrl(defaultTargetUrl);
    }

    /**
     * Calls the parent class {@code handle()} method to forward or redirect to the target URL, and
     * then calls {@code clearAuthenticationAttributes()} to remove any leftover session data.
     * 
     * <p> 调用父类的handle（）方法转发或重定向到目标URL，然后调用clearAuthenticationAttributes（）删除所有剩余的会话数据。
     */
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        handle(request, response, authentication);
        clearAuthenticationAttributes(request);
    }

    /**
     * Removes temporary authentication-related data which may have been stored in the session
     * during the authentication process.
     * 
     * <p> 删除在身份验证过程中可能已存储在会话中的与身份验证有关的临时数据。
     */
    protected final void clearAuthenticationAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session == null) {
            return;
        }

        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }
}
