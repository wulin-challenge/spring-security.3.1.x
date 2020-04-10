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


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.TextEscapeUtils;
import org.springframework.util.Assert;


/**
 * Processes an authentication form submission. Called {@code AuthenticationProcessingFilter} prior to Spring Security
 * 3.0.
 * 
 * <p> 处理身份验证表单提交。 在Spring Security 3.0之前称为AuthenticationProcessingFilter。
 * 
 * <p>
 * Login forms must present two parameters to this filter: a username and
 * password. The default parameter names to use are contained in the
 * static fields {@link #SPRING_SECURITY_FORM_USERNAME_KEY} and {@link #SPRING_SECURITY_FORM_PASSWORD_KEY}.
 * The parameter names can also be changed by setting the {@code usernameParameter} and {@code passwordParameter}
 * properties.
 * 
 * <p> 登录表单必须为此过滤器提供两个参数：用户名和密码。 要使用的默认参数名称包含在静态字段
 * SPRING_SECURITY_FORM_USERNAME_KEY和SPRING_SECURITY_FORM_PASSWORD_KEY中。 也可以通过设置
 * usernameParameter和passwordParameter属性来更改参数名称。
 * 
 * <p>
 * This filter by default responds to the URL {@code /j_spring_security_check}.
 * 
 * <p> 默认情况下，此过滤器响应URL / j_spring_security_check。
 *
 * @author Ben Alex
 * @author Colin Sampaleanu
 * @author Luke Taylor
 * @since 3.0
 */
public class UsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    //~ Static fields/initializers =====================================================================================

    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "j_username";
    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "j_password";
    /**
     * @deprecated If you want to retain the username, cache it in a customized {@code AuthenticationFailureHandler}
     */
    @Deprecated
    public static final String SPRING_SECURITY_LAST_USERNAME_KEY = "SPRING_SECURITY_LAST_USERNAME";

    private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
    private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;
    private boolean postOnly = true;

    //~ Constructors ===================================================================================================

    public UsernamePasswordAuthenticationFilter() {
        super("/j_spring_security_check");
    }

    //~ Methods ========================================================================================================

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        String username = obtainUsername(request);
        String password = obtainPassword(request);

        if (username == null) {
            username = "";
        }

        if (password == null) {
            password = "";
        }

        username = username.trim();

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);

        // Allow subclasses to set the "details" property
        // 允许子类设置“详细信息”属性
        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * Enables subclasses to override the composition of the password, such as by including additional values
     * and a separator.
     * 
     * <p> 允许子类覆盖密码的组成，例如通过包括其他值和分隔符。
     * 
     * <p>This might be used for example if a postcode/zipcode was required in addition to the
     * password. A delimiter such as a pipe (|) should be used to separate the password and extended value(s). The
     * <code>AuthenticationDao</code> will need to generate the expected password in a corresponding manner.</p>
     * 
     * <p> 例如，如果除密码外还需要邮政编码，则可以使用它。 应该使用分隔符（例如，竖线（|））来分隔密码和扩展值。 
     * AuthenticationDao将需要以相应的方式生成期望的密码。
     *
     * @param request so that request attributes can be retrieved
     * 
     * <p> 这样就可以检索请求属性
     *
     * @return the password that will be presented in the <code>Authentication</code> request token to the
     *         <code>AuthenticationManager</code>
     *         
     * <p> 将在身份验证请求令牌中提供给AuthenticationManager的密码
     */
    protected String obtainPassword(HttpServletRequest request) {
        return request.getParameter(passwordParameter);
    }

    /**
     * Enables subclasses to override the composition of the username, such as by including additional values
     * and a separator.
     * 
     * <p> 使子类能够覆盖用户名的组成，例如通过包括其他值和分隔符。
     *
     * @param request so that request attributes can be retrieved
     * 
     * <p> 这样就可以检索请求属性
     *
     * @return the username that will be presented in the <code>Authentication</code> request token to the
     *         <code>AuthenticationManager</code>
     *         
     * <p> 将在身份验证请求令牌中提供给AuthenticationManager的用户名
     */
    protected String obtainUsername(HttpServletRequest request) {
        return request.getParameter(usernameParameter);
    }

    /**
     * Provided so that subclasses may configure what is put into the authentication request's details
     * property.
     * 
     * <p> 提供以便子类可以配置放入身份验证请求的details属性的内容。
     *
     * @param request that an authentication request is being created for
     * 
     * <p> 正在为其创建身份验证请求
     * 
     * @param authRequest the authentication request object that should have its details set
     * 
     * <p> 应设置其详细信息的身份验证请求对象
     */
    protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }

    /**
     * Sets the parameter name which will be used to obtain the username from the login request.
     * 
     * <p> 设置参数名称，该名称将用于从登录请求中获取用户名。
     *
     * @param usernameParameter the parameter name. Defaults to "j_username".
     * 
     * <p> 参数名称。 默认为“ j_username”。
     */
    public void setUsernameParameter(String usernameParameter) {
        Assert.hasText(usernameParameter, "Username parameter must not be empty or null");
        this.usernameParameter = usernameParameter;
    }

    /**
     * Sets the parameter name which will be used to obtain the password from the login request..
     * 
     * <p> 设置参数名称，该名称将用于从登录请求中获取密码。
     *
     * @param passwordParameter the parameter name. Defaults to "j_password".
     * 
     * <p> 参数名称。 默认为“ j_password”。
     */
    public void setPasswordParameter(String passwordParameter) {
        Assert.hasText(passwordParameter, "Password parameter must not be empty or null");
        this.passwordParameter = passwordParameter;
    }

    /**
     * Defines whether only HTTP POST requests will be allowed by this filter.
     * If set to true, and an authentication request is received which is not a POST request, an exception will
     * be raised immediately and authentication will not be attempted. The <tt>unsuccessfulAuthentication()</tt> method
     * will be called as if handling a failed authentication.
     * 
     * <p> 定义此过滤器是否仅允许HTTP POST请求。 如果设置为true，并且收到不是POST请求的身份验证请求，则会立即引发异常，
     * 并且不会尝试进行身份验证。 将调用unsuccessfulAuthentication（）方法，就像处理身份验证失败一样。
     * 
     * <p>
     * Defaults to <tt>true</tt> but may be overridden by subclasses.
     * 
     * <p> 默认为true，但可能被子类覆盖。
     */
    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    public final String getUsernameParameter() {
        return usernameParameter;
    }

    public final String getPasswordParameter() {
        return passwordParameter;
    }
}
