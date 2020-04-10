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

package org.springframework.security.core.context;

import org.springframework.security.core.Authentication;

import java.io.Serializable;


/**
 * Interface defining the minimum security information associated with the
 * current thread of execution.
 * 
 * <p> 定义与当前执行线程关联的最小安全性信息的接口。
 *
 * <p>
 * The security context is stored in a {@link SecurityContextHolder}.
 * </p>
 *
 * <p> 安全上下文存储在SecurityContextHolder中。
 * 
 * @author Ben Alex
 */
public interface SecurityContext extends Serializable {
    //~ Methods ========================================================================================================

    /**
     * Obtains the currently authenticated principal, or an authentication request token.
     * 
     * <p> 获取当前已认证的主体或认证请求令牌。
     * 
     *
     * @return the <code>Authentication</code> or <code>null</code> if no authentication information is available
     * 
     * <p> Authentication；如果没有可用的身份验证信息，则为null
     * 
     */
    Authentication getAuthentication();

    /**
     * Changes the currently authenticated principal, or removes the authentication information.
     * 
     * <p> 更改当前已验证的主体，或删除验证信息。
     *
     * @param authentication the new <code>Authentication</code> token, or <code>null</code> if no further
     *        authentication information should be stored
     *        
     * <p> 新的身份验证令牌，如果不应再存储其他身份验证信息，则为null
     */
    void setAuthentication(Authentication authentication);
}
