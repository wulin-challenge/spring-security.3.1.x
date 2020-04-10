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

package org.springframework.security.core.userdetails;


/**
 * Core interface which loads user-specific data.
 * 
 * <p> 加载用户特定数据的核心接口。
 * 
 * <p>
 * It is used throughout the framework as a user DAO and is the strategy used by the
 * {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider DaoAuthenticationProvider}.
 * 
 * <p> 它在整个框架中都用作用户DAO，并且是DaoAuthenticationProvider使用的策略。
 *
 * <p>
 * The interface requires only one read-only method, which simplifies support for new data-access strategies.
 * 
 * <p> 该接口仅需要一种只读方法，从而简化了对新数据访问策略的支持。
 *
 * @see org.springframework.security.authentication.dao.DaoAuthenticationProvider
 * @see UserDetails
 *
 * @author Ben Alex
 */
public interface UserDetailsService {
    //~ Methods ========================================================================================================

    /**
     * Locates the user based on the username. In the actual implementation, the search may possibly be case
     * sensitive, or case insensitive depending on how the implementation instance is configured. In this case, the
     * <code>UserDetails</code> object that comes back may have a username that is of a different case than what was
     * actually requested..
     * 
     * <p> 根据用户名找到用户。 在实际的实现中，搜索可能区分大小写，或者不区分大小写，具体取决于实现实例的配置方式。 
     * 在这种情况下，返回的UserDetails对象的用户名可能与实际请求的用户名不同。
     *
     * @param username the username identifying the user whose data is required.
     * 
     * <p> 标识需要其数据的用户的用户名。
     *
     * @return a fully populated user record (never <code>null</code>)
     * 
     * <p> 完全填充的用户记录（绝不为null）
     *
     * @throws UsernameNotFoundException if the user could not be found or the user has no GrantedAuthority
     * 
     * <p> 如果找不到用户或用户没有GrantedAuthority
     */
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
