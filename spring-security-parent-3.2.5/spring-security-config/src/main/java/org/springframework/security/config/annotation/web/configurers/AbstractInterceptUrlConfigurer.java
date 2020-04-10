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
package org.springframework.security.config.annotation.web.configurers;

import java.util.List;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

/**
 * A base class for configuring the {@link FilterSecurityInterceptor}.
 * 
 * <p> 用于配置FilterSecurityInterceptor的基类。
 *
 * <h2>Security Filters</h2>
 * 
 * <p> 安全过滤器
 *
 * <p> The following Filters are populated
 * 
 * <p> 填充了以下过滤器
 *
 * <ul>
 *     <li>{@link FilterSecurityInterceptor}</li>
 * </ul>
  *
 * <h2>Shared Objects Created</h2>
 * 
 * <p> 创建共享对象
 *
 * <p> The following shared objects are populated to allow other {@link SecurityConfigurer}'s to customize:
 * 
 * <p> 填充了以下共享库，以允许其他SecurityConfigurer进行自定义：
 * 
 * <ul>
 *     <li>{@link FilterSecurityInterceptor}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 * 
 * <p> 使用的共享对象
 *
 * <p> The following shared objects are used:
 * 
 * <p> 使用以下共享对象：
 *
 * <ul>
 *     <li>{@link org.springframework.security.config.annotation.web.builders.HttpSecurity#getAuthenticationManager()}</li>
 * </ul>
 *
 *
 *
 * @param <C> the AbstractInterceptUrlConfigurer
 * @param <H> the type of {@link HttpSecurityBuilder} that is being configured
 * 
 * <p> <H>正在配置的HttpSecurityBuilder的类型
 *
 * @author Rob Winch
 * @since 3.2
 * @see ExpressionUrlAuthorizationConfigurer
 * @see UrlAuthorizationConfigurer
 */
abstract class AbstractInterceptUrlConfigurer<C extends AbstractInterceptUrlConfigurer<C,H>, H extends HttpSecurityBuilder<H>> extends
        AbstractHttpConfigurer<C, H>{
    private Boolean filterSecurityInterceptorOncePerRequest;

    private AccessDecisionManager accessDecisionManager;

    @Override
    public void configure(H http) throws Exception {
        FilterInvocationSecurityMetadataSource metadataSource = createMetadataSource(http);
        if(metadataSource == null) {
            return;
        }
        FilterSecurityInterceptor securityInterceptor = createFilterSecurityInterceptor(http, metadataSource, http.getSharedObject(AuthenticationManager.class));
        if(filterSecurityInterceptorOncePerRequest != null) {
            securityInterceptor.setObserveOncePerRequest(filterSecurityInterceptorOncePerRequest);
        }
        securityInterceptor = postProcess(securityInterceptor);
        http.addFilter(securityInterceptor);
        http.setSharedObject(FilterSecurityInterceptor.class, securityInterceptor);
    }

    /**
     * Subclasses should implement this method to provide a {@link FilterInvocationSecurityMetadataSource} for the
     * {@link FilterSecurityInterceptor}.
     * 
     * <p> 子类应实现此方法，以为FilterSecurityInterceptor提供FilterInvocationSecurityMetadataSource。
     *
     * @param http the builder to use
     *
     * @return the {@link FilterInvocationSecurityMetadataSource} to set on the {@link FilterSecurityInterceptor}.
     *         Cannot be null.
     *         
     * <p> 在FilterSecurityInterceptor上设置的FilterInvocationSecurityMetadataSource。 不能为null。
     */
    abstract FilterInvocationSecurityMetadataSource createMetadataSource(H http);

    /**
     * Subclasses should implement this method to provide the {@link AccessDecisionVoter} instances used to create the
     * default {@link AccessDecisionManager}
     * 
     * <p> 子类应实现此方法，以提供用于创建默认AccessDecisionManager的AccessDecisionVoter实例。
     *
     * @param http the builder to use
     *
     * @return the {@link AccessDecisionVoter} instances used to create the
     *         default {@link AccessDecisionManager}
     *         
     * <p> 用于创建默认AccessDecisionManager的AccessDecisionVoter实例
     */
    @SuppressWarnings("rawtypes")
    abstract List<AccessDecisionVoter> getDecisionVoters(H http);

    abstract class AbstractInterceptUrlRegistry<R extends AbstractInterceptUrlRegistry<R,T>,T> extends AbstractConfigAttributeRequestMatcherRegistry<T> {

        /**
         * Allows setting the {@link AccessDecisionManager}. If none is provided, a default {@l AccessDecisionManager} is
         * created.
         * 
         * <p> 允许设置AccessDecisionManager。 如果未提供任何内容，则会创建默认的{@l AccessDecisionManager}。
         *
         * @param accessDecisionManager the {@link AccessDecisionManager} to use
         * @return  the {@link AbstractInterceptUrlConfigurer} for further customization
         */
        public R accessDecisionManager(
                AccessDecisionManager accessDecisionManager) {
            AbstractInterceptUrlConfigurer.this.accessDecisionManager = accessDecisionManager;
            return getSelf();
        }

        /**
         * Allows setting if the {@link FilterSecurityInterceptor} should be only applied once per request (i.e. if the
         * filter intercepts on a forward, should it be applied again).
         * 
         * <p> 允许设置是否在每个请求中仅应用一次FilterSecurityInterceptor（即，如果过滤器在转发时拦截，则应再次应用）。
         *
         * @param filterSecurityInterceptorOncePerRequest if the {@link FilterSecurityInterceptor} should be only applied
         *                                                once per request
         *                                                
         * <p> 如果每个请求仅应将FilterSecurityInterceptor应用于一次
         * 
         * @return  the {@link AbstractInterceptUrlConfigurer} for further customization
         */
        public R filterSecurityInterceptorOncePerRequest(
                boolean filterSecurityInterceptorOncePerRequest) {
            AbstractInterceptUrlConfigurer.this.filterSecurityInterceptorOncePerRequest = filterSecurityInterceptorOncePerRequest;
            return getSelf();
        }

        /**
         * Returns a reference to the current object with a single suppression of
         * the type
         * 
         * <p> 返回对当前对象的引用，并带有单个抑制类型
         *
         * @return a reference to the current object
         */
        @SuppressWarnings("unchecked")
        private R getSelf() {
            return (R) this;
        }
    }

    /**
     * Creates the default {@code AccessDecisionManager}
     * @return the default {@code AccessDecisionManager}
     */
    private AccessDecisionManager createDefaultAccessDecisionManager(H http) {
        return new AffirmativeBased(getDecisionVoters(http));
    }

    /**
     * If currently null, creates a default {@link AccessDecisionManager} using
     * {@link #createDefaultAccessDecisionManager()}. Otherwise returns the {@link AccessDecisionManager}.
     * 
     * <p> 如果当前为null，则使用createDefaultAccessDecisionManager（）创建默认的AccessDecisionManager。 
     * 否则，返回AccessDecisionManager。
     *
     * @param http the builder to use
     *
     * @return the {@link AccessDecisionManager} to use
     */
    private AccessDecisionManager getAccessDecisionManager(H http) {
        if (accessDecisionManager == null) {
            accessDecisionManager = createDefaultAccessDecisionManager(http);
        }
        return accessDecisionManager;
    }

    /**
     * Creates the {@link FilterSecurityInterceptor}
     *
     * @param http the builder to use
     * @param metadataSource the {@link FilterInvocationSecurityMetadataSource} to use
     * @param authenticationManager the {@link AuthenticationManager} to use
     * @return the {@link FilterSecurityInterceptor}
     * @throws Exception
     */
    private FilterSecurityInterceptor createFilterSecurityInterceptor(H http, FilterInvocationSecurityMetadataSource metadataSource,
                                                                      AuthenticationManager authenticationManager) throws Exception {
        FilterSecurityInterceptor securityInterceptor = new FilterSecurityInterceptor();
        securityInterceptor.setSecurityMetadataSource(metadataSource);
        securityInterceptor.setAccessDecisionManager(getAccessDecisionManager(http));
        securityInterceptor.setAuthenticationManager(authenticationManager);
        securityInterceptor.afterPropertiesSet();
        return securityInterceptor;
    }
}