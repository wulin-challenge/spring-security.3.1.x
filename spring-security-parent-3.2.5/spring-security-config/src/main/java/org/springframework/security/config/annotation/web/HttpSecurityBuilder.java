/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web;

import javax.servlet.Filter;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.openid.OpenIDAuthenticationFilter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;

/**
 *
 * @author Rob Winch
 *
 * @param <H>
 */
public interface HttpSecurityBuilder<H extends HttpSecurityBuilder<H>> extends SecurityBuilder<DefaultSecurityFilterChain> {

    /**
     * Gets the {@link SecurityConfigurer} by its class name or
     * <code>null</code> if not found. Note that object hierarchies are not
     * considered.
     *
     * <p> 通过其类名称获取SecurityConfigurer；如果未找到，则返回null。 请注意，不考虑对象层次结构。
     * 
     * @param clazz the Class of the {@link SecurityConfigurer} to attempt to get.
     * 
     * <p> 尝试获取的SecurityConfigurer的类。
     */
    <C extends SecurityConfigurer<DefaultSecurityFilterChain, H>> C getConfigurer(
            Class<C> clazz);

    /**
     * Removes the {@link SecurityConfigurer} by its class name or
     * <code>null</code> if not found. Note that object hierarchies are not
     * considered.
     * 
     * <p> 通过其类名称删除SecurityConfigurer；如果找不到，则删除null。 请注意，不考虑对象层次结构。
     *
     * @param clazz the Class of the {@link SecurityConfigurer} to attempt to remove.
     * 
     * <p> 尝试删除的SecurityConfigurer的类。
     * 
     * @return the {@link SecurityConfigurer} that was removed or null if not found
     * 
     * <p> 被删除的SecurityConfigurer；如果找不到，则为null
     */
    <C extends SecurityConfigurer<DefaultSecurityFilterChain, H>> C removeConfigurer(Class<C> clazz);

    /**
     * Sets an object that is shared by multiple {@link SecurityConfigurer}.
     * 
     * <p> 设置由多个SecurityConfigurer共享的对象。
     *
     * @param sharedType the Class to key the shared object by.
     * 
     * <p> 用来作为共享对象密钥的Class。
     * 
     * @param object the Object to store
     * 
     * <p> 要存储的对象
     */
    <C> void setSharedObject(Class<C> sharedType, C object);

    /**
     * Gets a shared Object. Note that object heirarchies are not considered.
     * 
     * <p> 获取共享对象。 请注意，不考虑对象层次结构。
     *
     * @param sharedType the type of the shared Object
     * 
     * <p> 共享对象的类型
     * 
     * @return the shared Object or null if it is not found
     * 
     * <p> 共享对象；如果找不到，则为null
     */
    <C> C getSharedObject(Class<C> sharedType);

    /**
     * Allows adding an additional {@link AuthenticationProvider} to be used
     * 
     * <p> 允许添加额外的UserDetailsService来使用
     *
     * @param authenticationProvider the {@link AuthenticationProvider} to be added
     * 
     * <p> <p> 要添加的AuthenticationProvider
     * 
     * @return the {@link HttpSecurity} for further customizations
     * 
     * 
     * <p> HttpSecurity进行进一步的自定义
     */
    H authenticationProvider(
            AuthenticationProvider authenticationProvider);

    /**
     * Allows adding an additional {@link UserDetailsService} to be used
     *
     * @param userDetailsService the {@link UserDetailsService} to be added
     * @return the {@link HttpSecurity} for further customizations
     * 
     * <p> HttpSecurity进行进一步的自定义
     */
    H userDetailsService(
            UserDetailsService userDetailsService) throws Exception;

    /**
     * Allows adding a {@link Filter} after one of the known {@link Filter}
     * classes. The known {@link Filter} instances are either a {@link Filter}
     * listed in {@link #addFilter(Filter)} or a {@link Filter} that has already
     * been added using {@link #addFilterAfter(Filter, Class)} or
     * {@link #addFilterBefore(Filter, Class)}.
     * 
     * <p> 允许在已知的过滤器类之一之后添加过滤器。 已知的Filter实例是addFilter（Filter）中列出的
     * Filter或已经使用addFilterAfter（Filter，Class）或addFilterBefore（Filter，Class）添加的Filter。
     *
     * @param filter the {@link Filter} to register before the type {@code afterFilter}
     * 
     * <p> 要在类型afterFilter之前注册的过滤器
     * 
     * @param afterFilter the Class of the known {@link Filter}.
     * 
     * <p> 已知过滤器的类。
     * 
     * @return the {@link HttpSecurity} for further customizations
     * 
     * <p> HttpSecurity进行进一步的自定义
     */
    H addFilterAfter(Filter filter,
            Class<? extends Filter> afterFilter);

    /**
     * Allows adding a {@link Filter} before one of the known {@link Filter}
     * classes. The known {@link Filter} instances are either a {@link Filter}
     * listed in {@link #addFilter(Filter)} or a {@link Filter} that has already
     * been added using {@link #addFilterAfter(Filter, Class)} or
     * {@link #addFilterBefore(Filter, Class)}.
     * 
     * <p> 允许在已知的过滤器类之一之前添加过滤器。 已知的Filter实例是addFilter（Filter）中列出的
     * Filter或已经使用addFilterAfter（Filter，Class）或addFilterBefore（Filter，Class）添加的Filter。
     * 
     *
     * @param filter the {@link Filter} to register before the type {@code beforeFilter}
     * 
     * <p> 要在类型beforeFilter之前注册的过滤器
     * 
     * @param beforeFilter the Class of the known {@link Filter}.
     * 
     * <p> 已知过滤器的类。
     * 
     * @return the {@link HttpSecurity} for further customizations
     * 
     * <p> HttpSecurity进行进一步的自定义
     */
    H addFilterBefore(Filter filter,
            Class<? extends Filter> beforeFilter);

    /**
     * Adds a {@link Filter} that must be an instance of or extend one of the
     * Filters provided within the Security framework. The method ensures that
     * the ordering of the Filters is automatically taken care of.
     * 
     * <p> 添加一个筛选器，该筛选器必须是Security框架中提供的筛选器的实例或扩展。 该方法确保自动处理过滤器的顺序。
     * 
     *
     * The ordering of the Filters is:
     * 
     * <p>  过滤器的顺序为：
     *
     * <ul>
     * <li>{@link ChannelProcessingFilter}</li>
     * <li>{@link ConcurrentSessionFilter}</li>
     * <li>{@link SecurityContextPersistenceFilter}</li>
     * <li>{@link LogoutFilter}</li>
     * <li>{@link X509AuthenticationFilter}</li>
     * <li>{@link AbstractPreAuthenticatedProcessingFilter}</li>
     * <li>{@link org.springframework.security.cas.web.CasAuthenticationFilter}</li>
     * <li>{@link UsernamePasswordAuthenticationFilter}</li>
     * <li>{@link ConcurrentSessionFilter}</li>
     * <li>{@link OpenIDAuthenticationFilter}</li>
     * <li>{@link DefaultLoginPageGeneratingFilter}</li>
     * <li>{@link ConcurrentSessionFilter}</li>
     * <li>{@link DigestAuthenticationFilter}</li>
     * <li>{@link BasicAuthenticationFilter}</li>
     * <li>{@link RequestCacheAwareFilter}</li>
     * <li>{@link SecurityContextHolderAwareRequestFilter}</li>
     * <li>{@link JaasApiIntegrationFilter}</li>
     * <li>{@link RememberMeAuthenticationFilter}</li>
     * <li>{@link AnonymousAuthenticationFilter}</li>
     * <li>{@link SessionManagementFilter}</li>
     * <li>{@link ExceptionTranslationFilter}</li>
     * <li>{@link FilterSecurityInterceptor}</li>
     * <li>{@link SwitchUserFilter}</li>
     * </ul>
     *
     * @param filter the {@link Filter} to add - 要添加的filter
     * @return the {@link HttpSecurity} for further customizations
     * 
     * <p> HttpSecurity进行进一步的自定义
     */
    H addFilter(Filter filter);
}