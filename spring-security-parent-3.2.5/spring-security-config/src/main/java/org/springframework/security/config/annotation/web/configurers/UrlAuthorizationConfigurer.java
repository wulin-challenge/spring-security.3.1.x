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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;


/**
 * Adds URL based authorization using
 * {@link DefaultFilterInvocationSecurityMetadataSource}. At least one
 * {@link org.springframework.web.bind.annotation.RequestMapping} needs to be
 * mapped to {@link ConfigAttribute}'s for this
 * {@link SecurityContextConfigurer} to have meaning. 
 * 
 * <p> 使用DefaultFilterInvocationSecurityMetadataSource添加基于URL的授权。 
 * 至少需要将一个org.springframework.web.bind.annotation.RequestMapping映射到ConfigAttribute，
 * 此SecurityContextConfigurer才有意义。
 * 
 * <h2>Security Filters</h2>
 * <p> 安全过滤器
 * 
 * <p>
 * Usage includes applying the {@link UrlAuthorizationConfigurer} and then
 * modifying the StandardInterceptUrlRegistry. For example:
 * </p>
 * 
 * <p> 用法包括应用UrlAuthorizationConfigurer，然后修改StandardInterceptUrlRegistry。 例如：
 *
 * <pre>
 * protected void configure(HttpSecurity http) throws Exception {
 *     http
 *          .apply(new UrlAuthorizationConfigurer<HttpSecurity>()).getRegistry()
 *              .antMatchers("/users**","/sessions/**").hasRole("USER")
 *              .antMatchers("/signup").hasRole("ANONYMOUS")
 *              .anyRequest().hasRole("USER");
 * }
 * </pre>
 *
 * The following Filters are populated
 * 
 * <p> 填充了以下过滤器
 *
 * <ul>
 * <li>
 * {@link org.springframework.security.web.access.intercept.FilterSecurityInterceptor}
 * </li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * <p> 创建共享对象
 *
 * The following shared objects are populated to allow other
 * {@link org.springframework.security.config.annotation.SecurityConfigurer}'s
 * to customize:
 * 
 * <p> 填充了以下共享库，以允许其他org.springframework.security.config.annotation.SecurityConfigurer进行自定义：
 * 
 * <ul>
 * <li>
 * {@link org.springframework.security.web.access.intercept.FilterSecurityInterceptor}
 * </li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 * 
 * <p> 使用的共享对象
 * 
 *
 * <p> The following shared objects are used:
 * 
 * <p> 使用以下共享库：
 *
 * <ul>
 * <li>
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity#getAuthenticationManager()}
 * </li>
 * </ul>
 *
 * @param <H>
 *            the type of {@link HttpSecurityBuilder} that is being configured
 *            
 * <p> 正在配置的HttpSecurityBuilder的类型
 * 
 * @param <C>
 *            the type of object that is being chained
 *            
 * <p> 链接对象的类型
 *
 * @author Rob Winch
 * @since 3.2
 * @see ExpressionUrlAuthorizationConfigurer
 */
public final class UrlAuthorizationConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractInterceptUrlConfigurer<UrlAuthorizationConfigurer<H>,H> {
    private final StandardInterceptUrlRegistry REGISTRY = new StandardInterceptUrlRegistry();

    /**
     * The StandardInterceptUrlRegistry is what users will interact with after
     * applying the {@link UrlAuthorizationConfigurer}.
     *
     * @return
     */
    public StandardInterceptUrlRegistry getRegistry() {
        return REGISTRY;
    }

    /**
     * Adds an {@link ObjectPostProcessor} for this class.
     *
     * @param objectPostProcessor
     * @return the {@link UrlAuthorizationConfigurer} for further customizations
     */
    public UrlAuthorizationConfigurer<H> withObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
        addObjectPostProcessor(objectPostProcessor);
        return this;
    }

    public class StandardInterceptUrlRegistry extends ExpressionUrlAuthorizationConfigurer<H>.AbstractInterceptUrlRegistry<StandardInterceptUrlRegistry,AuthorizedUrl> {

        @Override
        protected final AuthorizedUrl chainRequestMatchersInternal(List<RequestMatcher> requestMatchers) {
            return new AuthorizedUrl(requestMatchers);
        }

        /**
         * Adds an {@link ObjectPostProcessor} for this class.
         *
         * @param objectPostProcessor
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customizations
         */
        public StandardInterceptUrlRegistry withObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
            addObjectPostProcessor(objectPostProcessor);
            return this;
        }

        public H and() {
            return UrlAuthorizationConfigurer.this.and();
        }

    }

    /**
     * Creates the default {@link AccessDecisionVoter} instances used if an
     * {@link AccessDecisionManager} was not specified using
     * {@link #accessDecisionManager(AccessDecisionManager)}.
     *
     * @param http the builder to use
     */
    @Override
    @SuppressWarnings("rawtypes")
    final List<AccessDecisionVoter> getDecisionVoters(H http) {
        List<AccessDecisionVoter> decisionVoters = new ArrayList<AccessDecisionVoter>();
        decisionVoters.add(new RoleVoter());
        decisionVoters.add(new AuthenticatedVoter());
        return decisionVoters;
    }

    /**
     * Creates the {@link FilterInvocationSecurityMetadataSource} to use. The
     * implementation is a {@link DefaultFilterInvocationSecurityMetadataSource}.
     *
     * @param http the builder to use
     */
    @Override
    FilterInvocationSecurityMetadataSource createMetadataSource(H http) {
        return new DefaultFilterInvocationSecurityMetadataSource(REGISTRY.createRequestMap());
    }

    /**
     * Adds a mapping of the {@link RequestMatcher} instances to the {@link ConfigAttribute} instances.
     * @param requestMatchers the {@link RequestMatcher} instances that should map to the provided {@link ConfigAttribute} instances
     * @param configAttributes the {@link ConfigAttribute} instances that should be mapped by the {@link RequestMatcher} instances
     * @return the {@link UrlAuthorizationConfigurer} for further customizations
     */
    private StandardInterceptUrlRegistry addMapping(Iterable<? extends RequestMatcher> requestMatchers, Collection<ConfigAttribute> configAttributes) {
        for(RequestMatcher requestMatcher : requestMatchers) {
            REGISTRY.addMapping(new AbstractConfigAttributeRequestMatcherRegistry.UrlMapping(requestMatcher, configAttributes));
        }
        return REGISTRY;
    }

    /**
     * Creates a String for specifying a user requires a role.
     *
     * @param role
     *            the role that should be required which is prepended with ROLE_
     *            automatically (i.e. USER, ADMIN, etc). It should not start
     *            with ROLE_
     * @return the {@link ConfigAttribute} expressed as a String
     */
    private static String hasRole(String role) {
        Assert.isTrue(
                !role.startsWith("ROLE_"),
                role
                        + " should not start with ROLE_ since ROLE_ is automatically prepended when using hasRole. Consider using hasAuthority or access instead.");
        return "ROLE_" + role;
    }

    /**
     * Creates a String for specifying that a user requires one of many roles.
     *
     * @param roles
     *            the roles that the user should have at least one of (i.e.
     *            ADMIN, USER, etc). Each role should not start with ROLE_ since
     *            it is automatically prepended already.
     * @return the {@link ConfigAttribute} expressed as a String
     */
    private static String[] hasAnyRole(String... roles) {
        for(int i=0;i<roles.length;i++) {
            roles[i] = "ROLE_" + roles[i];
        }
        return roles;
    }

    /**
     * Creates a String for specifying that a user requires one of many authorities
     * @param authorities the authorities that the user should have at least one of (i.e. ROLE_USER, ROLE_ADMIN, etc).
     * @return the {@link ConfigAttribute} expressed as a String.
     */
    private static String[] hasAnyAuthority(String... authorities) {
        return authorities;
    }

    /**
     * Maps the specified {@link RequestMatcher} instances to {@link ConfigAttribute} instances.
     *
     * @author Rob Winch
     * @since 3.2
     */
    public final class AuthorizedUrl {
        private final List<RequestMatcher> requestMatchers;

        /**
         * Creates a new instance
         * @param requestMatchers the {@link RequestMatcher} instances to map to some {@link ConfigAttribute} instances.
         * @see UrlAuthorizationConfigurer#chainRequestMatchers(List)
         */
        private AuthorizedUrl(List<RequestMatcher> requestMatchers) {
            Assert.notEmpty(requestMatchers, "requestMatchers must contain at least one value");
            this.requestMatchers = requestMatchers;
        }

        /**
         * Specifies a user requires a role.
         *
         * @param role
         *            the role that should be required which is prepended with ROLE_
         *            automatically (i.e. USER, ADMIN, etc). It should not start
         *            with ROLE_
         * the {@link UrlAuthorizationConfigurer} for further customization
         */
        public StandardInterceptUrlRegistry hasRole(String role) {
            return access(UrlAuthorizationConfigurer.hasRole(role));
        }

        /**
         * Specifies that a user requires one of many roles.
         *
         * @param roles
         *            the roles that the user should have at least one of (i.e.
         *            ADMIN, USER, etc). Each role should not start with ROLE_ since
         *            it is automatically prepended already.
         * @return the {@link UrlAuthorizationConfigurer} for further customization
         */
        public StandardInterceptUrlRegistry hasAnyRole(String... roles) {
            return access(UrlAuthorizationConfigurer.hasAnyRole(roles));
        }

        /**
         * Specifies a user requires an authority.
         *
         * @param authority
         *            the authority that should be required
         * @return the {@link UrlAuthorizationConfigurer} for further customization
         */
        public StandardInterceptUrlRegistry hasAuthority(String authority) {
            return access(authority);
        }

        /**
         * Specifies that a user requires one of many authorities
         * @param authorities the authorities that the user should have at least one of (i.e. ROLE_USER, ROLE_ADMIN, etc).
         * @return the {@link UrlAuthorizationConfigurer} for further customization
         */
        public StandardInterceptUrlRegistry hasAnyAuthority(String... authorities) {
            return access(UrlAuthorizationConfigurer.hasAnyAuthority(authorities));
        }

        /**
         * Specifies that an anonymous user is allowed access
         * @return the {@link UrlAuthorizationConfigurer} for further customization
         */
        public StandardInterceptUrlRegistry anonymous() {
            return hasRole("ROLE_ANONYMOUS");
        }

        /**
         * Specifies that the user must have the specified {@link ConfigAttribute}'s
         * @param attributes the {@link ConfigAttribute}'s that restrict access to a URL
         * @return the {@link UrlAuthorizationConfigurer} for further customization
         */
        public StandardInterceptUrlRegistry access(String... attributes) {
            addMapping(requestMatchers, SecurityConfig.createList(attributes));
            return UrlAuthorizationConfigurer.this.REGISTRY;
        }
    }
}