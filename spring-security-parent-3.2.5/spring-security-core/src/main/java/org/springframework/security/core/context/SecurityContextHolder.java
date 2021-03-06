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

import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Constructor;


/**
 * Associates a given {@link SecurityContext} with the current execution thread.
 * 
 * <p> 将给定的SecurityContext与当前执行线程关联。
 * <p>
 * This class provides a series of static methods that delegate to an instance of
 * {@link org.springframework.security.core.context.SecurityContextHolderStrategy}. The purpose of the class is to provide a
 * convenient way to specify the strategy that should be used for a given JVM.
 * This is a JVM-wide setting, since everything in this class is <code>static</code> to facilitate ease of use in
 * calling code.
 * 
 * <p> 此类提供了一系列静态方法，这些方法委托给org.springframework.security.core.context.SecurityContextHolderStrategy
 * 的实例。该类的目的是提供一种方便的方法来指定应用于给定JVM的策略。这是JVM范围的设置，因为此类中的所有内容都是静态的，以便于调用代码。
 * <p>
 * To specify which strategy should be used, you must provide a mode setting. A mode setting is one of the
 * three valid <code>MODE_</code> settings defined as <code>static final</code> fields, or a fully qualified classname
 * to a concrete implementation of {@link org.springframework.security.core.context.SecurityContextHolderStrategy} that
 * provides a public no-argument constructor.
 * 
 * <p> 若要指定应使用的策略，必须提供模式设置。模式设置是定义为静态最终字段的三个有效MODE_设置之一，或者是提供公共无参数构造函数的
 * org.springframework.security.core.context.SecurityContextHolderStrategy的具体实现的完全限定的类名。
 * 
 * <p>
 * There are two ways to specify the desired strategy mode <code>String</code>. The first is to specify it via
 * the system property keyed on {@link #SYSTEM_PROPERTY}. The second is to call {@link #setStrategyName(String)}
 * before using the class. If neither approach is used, the class will default to using {@link #MODE_THREADLOCAL},
 * which is backwards compatible, has fewer JVM incompatibilities and is appropriate on servers (whereas {@link
 * #MODE_GLOBAL} is definitely inappropriate for server use).
 * 
 * <p> 有两种方法可以指定所需的策略模式字符串。首先是通过键入SYSTEM_PROPERTY的系统属性来指定它。第二种是在使用类之前调用​​
 * setStrategyName（String）。如果两种方法均未使用，则该类将默认使用向后兼容的MODE_THREADLOCAL，JVM的不兼容性更少，
 * 并且适用于服务器（而MODE_GLOBAL绝对不适用于服务器）。
 *
 * @author Ben Alex
 *
 */
public class SecurityContextHolder {
    //~ Static fields/initializers =====================================================================================

    public static final String MODE_THREADLOCAL = "MODE_THREADLOCAL";
    public static final String MODE_INHERITABLETHREADLOCAL = "MODE_INHERITABLETHREADLOCAL";
    public static final String MODE_GLOBAL = "MODE_GLOBAL";
    public static final String SYSTEM_PROPERTY = "spring.security.strategy";
    private static String strategyName = System.getProperty(SYSTEM_PROPERTY);
    private static SecurityContextHolderStrategy strategy;
    private static int initializeCount = 0;

    static {
        initialize();
    }

    //~ Methods ========================================================================================================

    /**
     * Explicitly clears the context value from the current thread.
     * 
     * <p> 从当前线程中明确清除上下文值。
     */
    public static void clearContext() {
        strategy.clearContext();
    }

    /**
     * Obtain the current <code>SecurityContext</code>.
     * 
     * <p> 获取当前的SecurityContext。
     *
     * @return the security context (never <code>null</code>)
     * 
     * <p> 安全上下文（绝不为null）
     */
    public static SecurityContext getContext() {
        return strategy.getContext();
    }

    /**
     * Primarily for troubleshooting purposes, this method shows how many times the class has re-initialized its
     * <code>SecurityContextHolderStrategy</code>.
     * 
     * <p> 主要用于故障排除，此方法显示该类已重新初始化其SecurityContextHolderStrategy的次数。
     *
     * @return the count (should be one unless you've called {@link #setStrategyName(String)} to switch to an alternate
     *         strategy.
     *         
     * <p> 计数（除非您已调用setStrategyName（String）切换到其他策略，否则应为1）。
     */
    public static int getInitializeCount() {
        return initializeCount;
    }

    private static void initialize() {
        if ((strategyName == null) || "".equals(strategyName)) {
            // Set default
            strategyName = MODE_THREADLOCAL;
        }

        if (strategyName.equals(MODE_THREADLOCAL)) {
            strategy = new ThreadLocalSecurityContextHolderStrategy();
        } else if (strategyName.equals(MODE_INHERITABLETHREADLOCAL)) {
            strategy = new InheritableThreadLocalSecurityContextHolderStrategy();
        } else if (strategyName.equals(MODE_GLOBAL)) {
            strategy = new GlobalSecurityContextHolderStrategy();
        } else {
            // Try to load a custom strategy
            try {
                Class<?> clazz = Class.forName(strategyName);
                Constructor<?> customStrategy = clazz.getConstructor();
                strategy = (SecurityContextHolderStrategy) customStrategy.newInstance();
            } catch (Exception ex) {
                ReflectionUtils.handleReflectionException(ex);
            }
        }

        initializeCount++;
    }

    /**
     * Associates a new <code>SecurityContext</code> with the current thread of execution.
     * 
     * <p> 将新的SecurityContext与当前执行线程相关联。
     *
     * @param context the new <code>SecurityContext</code> (may not be <code>null</code>)
     * 
     * <p> 新的SecurityContext（不能为null）
     */
    public static void setContext(SecurityContext context) {
        strategy.setContext(context);
    }

    /**
     * Changes the preferred strategy. Do <em>NOT</em> call this method more than once for a given JVM, as it
     * will re-initialize the strategy and adversely affect any existing threads using the old strategy.
     * 
     * <p> 更改首选策略。 对于给定的JVM，不要多次调用此方法，因为它将重新初始化该策略，并使用旧策略对任何现有线程产生不利影响。
     *
     * @param strategyName the fully qualified class name of the strategy that should be used.
     * 
     * <p> 应使用的策略的完全限定的类名。
     */
    public static void setStrategyName(String strategyName) {
        SecurityContextHolder.strategyName = strategyName;
        initialize();
    }

    /**
     * Allows retrieval of the context strategy. See SEC-1188.
     * 
     * <p> 允许检索上下文策略。 参见SEC-1188。
     *
     * @return the configured strategy for storing the security context.
     * 
     * <p> 用于存储安全上下文的已配置策略。
     */
    public static SecurityContextHolderStrategy getContextHolderStrategy() {
        return strategy;
    }

    /**
     * Delegates the creation of a new, empty context to the configured strategy.
     * 
     * <p> 将创建新的空上下文委派给已配置的策略。
     */
    public static SecurityContext createEmptyContext() {
        return strategy.createEmptyContext();
    }

    public String toString() {
        return "SecurityContextHolder[strategy='" + strategyName + "'; initializeCount=" + initializeCount + "]";
    }
}
