package org.springframework.security.web.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;

/**
 * Strategy used to handle a failed authentication attempt.
 * 
 * <p> 用于处理失败的身份验证尝试的策略。
 * 
 * <p>
 * Typical behaviour might be to redirect the user to the authentication page (in the case of a form login) to
 * allow them to try again. More sophisticated logic might be implemented depending on the type of the exception.
 * For example, a {@link CredentialsExpiredException} might cause a redirect to a web controller which allowed the
 * user to change their password.
 * 
 * <p> 典型的行为可能是将用户重定向到身份验证页面（在表单登录的情况下）以允许他们重试。 根据异常的类型，可以实现更复杂的逻辑。 例如，CredentialsExpiredException可能导致重定向到Web控制器，从而允许用户更改其密码。
 *
 * @author Luke Taylor
 * @since 3.0
 */
public interface AuthenticationFailureHandler {

    /**
     * Called when an authentication attempt fails.
     * 
     * <p> 身份验证尝试失败时调用。
     * 
     * @param request the request during which the authentication attempt occurred.
     * 
     * <p> 尝试进行身份验证的请求。
     * 
     * @param response the response.
     * @param exception the exception which was thrown to reject the authentication request.
     * 
     * <p> 被抛出以拒绝身份验证请求的异常。
     */
    void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException;
}
