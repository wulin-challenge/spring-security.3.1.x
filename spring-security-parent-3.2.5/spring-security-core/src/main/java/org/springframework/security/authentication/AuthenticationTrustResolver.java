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

/**
 * Evaluates <code>Authentication</code> tokens
 * 
 * <p> 评估身份验证令牌
 *
 * @author Ben Alex
 */
public interface AuthenticationTrustResolver {
    //~ Methods ========================================================================================================

    /**
     * Indicates whether the passed <code>Authentication</code> token represents an anonymous user. Typically
     * the framework will call this method if it is trying to decide whether an <code>AccessDeniedException</code>
     * should result in a final rejection (i.e. as would be the case if the principal was non-anonymous/fully
     * authenticated) or direct the principal to attempt actual authentication (i.e. as would be the case if the
     * <code>Authentication</code> was merely anonymous).
     *
     * <p> 指示传递的身份验证令牌是否代表匿名用户。 通常，如果框架试图确定AccessDeniedException应该导致最终拒绝
     * （即，如果主体是非匿名/完全认证的，则是这种情况）还是指示主体尝试进行实际的认证（即，则框架）将调用此方法。 （如果身份验证只是匿名的话）。
     * 
     * @param authentication to test (may be <code>null</code> in which case the method will always return
     *        <code>false</code>)
     *        
     * <p> 测试（可能为null，在这种情况下，该方法将始终返回false）
     *
     * @return <code>true</code> the passed authentication token represented an anonymous principal, <code>false</code>
     *         otherwise
     *         
     * <p> 传递的身份验证令牌为true表示匿名主体，否则为false
     */
    boolean isAnonymous(Authentication authentication);

    /**
     * Indicates whether the passed <code>Authentication</code> token represents user that has been remembered
     * (i.e. not a user that has been fully authenticated).
     * 
     * <p> 指示所传递的身份验证令牌是否代表已被记住的用户（即不是经过完全身份验证的用户）。
     * 
     * <p>
     * The method is provided to assist with custom <code>AccessDecisionVoter</code>s and the like that you
     * might develop. Of course, you don't need to use this method either and can develop your own "trust level"
     * hierarchy instead.
     * 
     * <p> 提供该方法是为了帮助您开发自定义AccessDecisionVoters等。 当然，您也不需要使用此方法，而是可以开发自己的“信任级别”层次结构。
     *
     * @param authentication to test (may be <code>null</code> in which case the method will always return
     *        <code>false</code>)
     *        
     * <p> 测试（可能为null，在这种情况下，该方法将始终返回false）
     *
     * @return <code>true</code> the passed authentication token represented a principal authenticated using a
     *         remember-me token, <code>false</code> otherwise
     *         
     * <p> 传递的身份验证令牌为true表示使用“记住我”令牌进行身份验证的主体，否则为false
     */
    boolean isRememberMe(Authentication authentication);
}
