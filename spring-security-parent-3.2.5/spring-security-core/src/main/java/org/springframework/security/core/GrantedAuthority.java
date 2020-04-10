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

package org.springframework.security.core;

import java.io.Serializable;

import org.springframework.security.access.AccessDecisionManager;

/**
 * Represents an authority granted to an {@link Authentication} object.
 * 
 * <p> 表示授予Authentication对象的权限。
 *
 * <p>
 * A <code>GrantedAuthority</code> must either represent itself as a
 * <code>String</code> or be specifically supported by an  {@link
 * AccessDecisionManager}.
 * 
 * <p> GrantedAuthority必须将其自身表示为String或由AccessDecisionManager专门支持。
 *
 * @author Ben Alex
 */
public interface GrantedAuthority extends Serializable {
    //~ Methods ========================================================================================================

    /**
     * If the <code>GrantedAuthority</code> can be represented as a <code>String</code> and that
     * <code>String</code> is sufficient in precision to be relied upon for an access control decision by an {@link
     * AccessDecisionManager} (or delegate), this method should return such a <code>String</code>.
     * 
     * <p> 如果GrantedAuthority可以表示为一个String，并且该String的精度足以由
     * AccessDecisionManager（或委托）进行访问控制决策，则此方法应返回这样的String。
     * 
     * <p>
     * If the <code>GrantedAuthority</code> cannot be expressed with sufficient precision as a <code>String</code>,
     * <code>null</code> should be returned. Returning <code>null</code> will require an
     * <code>AccessDecisionManager</code> (or delegate) to specifically support the <code>GrantedAuthority</code>
     * implementation, so returning <code>null</code> should be avoided unless actually required.
     * 
     * <p> 如果GrantedAuthority无法以足够的精度表示为String，则应返回null。 返回null将需要一个
     * AccessDecisionManager（或委托）来专门支持GrantedAuthority实现，因此，除非实际需要，否则应避免返回null。
     *
     * @return a representation of the granted authority (or <code>null</code> if the granted authority cannot be
     *         expressed as a <code>String</code> with sufficient precision).
     *         
     * <p> 授予的权限的表示形式（如果不能以足够的精度将授予的权限表示为String，则为null）。
     */
    String getAuthority();
}
