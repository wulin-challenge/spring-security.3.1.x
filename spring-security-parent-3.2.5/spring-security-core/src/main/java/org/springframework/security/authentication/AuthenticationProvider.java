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

package org.springframework.security.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;


/**
 * Indicates a class can process a specific  {@link
 * org.springframework.security.core.Authentication} implementation.
 * 
 * <p> 表示一个类可以处理特定的org.springframework.security.core.Authentication实现。
 *
 * @author Ben Alex
 */
public interface AuthenticationProvider {
    //~ Methods ========================================================================================================

    /**
     * Performs authentication with the same contract as {@link
     * org.springframework.security.authentication.AuthenticationManager#authenticate(Authentication)}.
     * 
     * <p> 使用与org.springframework.security.authentication.AuthenticationManager.authenticate（Authentication）
     * 相同的合同执行身份验证。
     *
     * @param authentication the authentication request object.
     * 
     * <p> 身份验证请求对象。
     *
     * @return a fully authenticated object including credentials. May return <code>null</code> if the
     *         <code>AuthenticationProvider</code> is unable to support authentication of the passed
     *         <code>Authentication</code> object. In such a case, the next <code>AuthenticationProvider</code> that
     *         supports the presented <code>Authentication</code> class will be tried.
     *         
     * <p> 包含凭据的经过完全认证的对象。 如果AuthenticationProvider无法支持传递的Authentication对象的身份验证，则可以返回null。 
     * 在这种情况下，将尝试支持所提供的Authentication类的下一个AuthenticationProvider。
     * 
     *
     * @throws AuthenticationException if authentication fails.
     */
    Authentication authenticate(Authentication authentication)
        throws AuthenticationException;

    /**
     * Returns <code>true</code> if this <Code>AuthenticationProvider</code> supports the indicated
     * <Code>Authentication</code> object.
     * 
     * <p> 如果此AuthenticationProvider支持指定的Authentication对象，则返回true。
     * 
     * <p>
     * Returning <code>true</code> does not guarantee an <code>AuthenticationProvider</code> will be able to
     * authenticate the presented instance of the <code>Authentication</code> class. It simply indicates it can support
     * closer evaluation of it. An <code>AuthenticationProvider</code> can still return <code>null</code> from the
     * {@link #authenticate(Authentication)} method to indicate another <code>AuthenticationProvider</code> should be
     * tried.
     * 
     * <p> 返回true不能保证AuthenticationProvider将能够对Authentication类的所提供实例进行身份验证。 它只是表明它可以支持对其进行更仔细的评估。
     *  AuthenticationProvider仍可以从authenticate（Authentication）方法返回null，以指示应尝试使用另一个AuthenticationProvider。
     * 
     * </p>
     * <p>Selection of an <code>AuthenticationProvider</code> capable of performing authentication is
     * conducted at runtime the <code>ProviderManager</code>.</p>
     * 
     * <p> 能够执行身份验证的AuthenticationProvider的选择在ProviderManager的运行时进行。
     *
     * @param authentication
     *
     * @return <code>true</code> if the implementation can more closely evaluate the <code>Authentication</code> class
     *         presented
     *         
     * <p> 如果实现可以更紧密地评估所提供的Authentication类，则为true
     */
    boolean supports(Class<?> authentication);
}
