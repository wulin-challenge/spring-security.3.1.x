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

/**
 * A strategy for storing security context information against a thread.
 *
 * <p> 一种针对线程存储安全上下文信息的策略。
 * 
 * <p>
 * The preferred strategy is loaded by {@link SecurityContextHolder}.
 * 
 * <p> 首选策略由SecurityContextHolder加载。
 *
 * @author Ben Alex
 */
public interface SecurityContextHolderStrategy {
    //~ Methods ========================================================================================================

    /**
     * Clears the current context.
     * 
     * <p> 清除当前上下文。
     */
    void clearContext();

    /**
     * Obtains the current context.
     * 
     * <p> 获取当前上下文。
     *
     * @return a context (never <code>null</code> - create a default implementation if necessary)
     * 
     * <p> 上下文（绝不为null-必要时创建默认实现）
     */
    SecurityContext getContext();

    /**
     * Sets the current context.
     * 
     * <p> 设置当前上下文。
     *
     * @param context to the new argument (should never be <code>null</code>, although implementations must check if
     *        <code>null</code> has been passed and throw an <code>IllegalArgumentException</code> in such cases)
     *        
     * <p> 到新参数（永远不应为null，尽管实现必须检查是否已传递null并在这种情况下抛出IllegalArgumentException）
     */
    void setContext(SecurityContext context);

    /**
     * Creates a new, empty context implementation, for use by <tt>SecurityContextRepository</tt> implementations,
     * when creating a new context for the first time.
     * 
     * <p> 首次创建新上下文时，创建一个新的空上下文实现，以供SecurityContextRepository实现使用。
     *
     * @return the empty context. - 空的上下文
     */
    SecurityContext createEmptyContext();
}
