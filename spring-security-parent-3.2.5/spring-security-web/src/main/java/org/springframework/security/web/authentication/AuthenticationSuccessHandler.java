package org.springframework.security.web.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;

/**
 * Strategy used to handle a successful user authentication.
 * 
 * <p> 用于处理成功的用户身份验证的策略。
 * 
 * <p>
 * Implementations can do whatever they want but typical behaviour would be to control the navigation to the
 * subsequent destination (using a redirect or a forward). For example, after a user has logged in by submitting a
 * login form, the application needs to decide where they should be redirected to afterwards
 * (see {@link AbstractAuthenticationProcessingFilter} and subclasses). Other logic may also be included if required.
 *
 * <p> 实现可以执行他们想要的任何事情，但是典型的行为是控制到后续目标的导航（使用重定向或转发）。 例如，在用户通过提交登录表单登录后，应用程序需要确定之后应将其重定向到何处（请参阅AbstractAuthenticationProcessingFilter和子类）。 如果需要，还可以包括其他逻辑。
 * 
 * @author Luke Taylor
 * @since 3.0
 */
public interface AuthenticationSuccessHandler {

    /**
     * Called when a user has been successfully authenticated.
     * 
     * <p> 成功验证用户时调用。
     *
     * @param request the request which caused the successful authentication
     * 
     * <p> 导致成功认证的请求
     * 
     * @param response the response
     * @param authentication the <tt>Authentication</tt> object which was created during the authentication process.
     * 
     * <p> 在身份验证过程中创建的身份验证对象。
     */
    void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException;

}
