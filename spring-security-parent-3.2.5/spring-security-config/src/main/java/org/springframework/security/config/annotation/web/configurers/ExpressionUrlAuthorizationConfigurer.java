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
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Adds URL based authorization based upon SpEL expressions to an application. At least one
 * {@link org.springframework.web.bind.annotation.RequestMapping} needs to be mapped to {@link ConfigAttribute}'s for
 * this {@link SecurityContextConfigurer} to have meaning.
 * 
 * <p> 将基于SpEL表达式的基于URL的授权添加到应用程序。 至少需要将一个
 * org.springframework.web.bind.annotation.RequestMapping映射到ConfigAttribute，此SecurityContextConfigurer才有意义。
 * 
 * <h2>Security Filters</h2>
 * 
 * <p> 安全过滤器
 *
 * <p> The following Filters are populated
 * 
 * <p> 已填充以下过滤器
 *
 * <ul>
 *     <li>{@link org.springframework.security.web.access.intercept.FilterSecurityInterceptor}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 * 
 * <p> 创建共享对象
 *
 * <p>  The following shared objects are populated to allow other {@link org.springframework.security.config.annotation.SecurityConfigurer}'s to customize:
 * 
 * <p> 填充了以下共享库，以允许其他org.springframework.security.config.annotation.SecurityConfigurer进行自定义：
 *
 * <ul>
 *     <li>{@link org.springframework.security.web.access.intercept.FilterSecurityInterceptor}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 * 
 * <p> 使用的共享对象
 *
 * <ul>
 * <li>{@link AuthenticationTrustResolver} is optionally used to populate the {@link DefaultWebSecurityExpressionHandler}</li>
 * <li> AuthenticationTrustResolver可选地用于填充DefaultWebSecurityExpressionHandler
 * </ul>
 *
 * @param <H> the type of {@link HttpSecurityBuilder} that is being configured
 * 
 * <p> <H>正在配置的HttpSecurityBuilder的类型
 *
 * @author Rob Winch
 * @since 3.2
 * @see {@link org.springframework.security.config.annotation.web.builders.HttpSecurity#authorizeRequests()}
 */
public final class ExpressionUrlAuthorizationConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractInterceptUrlConfigurer<ExpressionUrlAuthorizationConfigurer<H>,H> {
    static final String permitAll = "permitAll";
    private static final String denyAll = "denyAll";
    private static final String anonymous = "anonymous";
    private static final String authenticated = "authenticated";
    private static final String fullyAuthenticated = "fullyAuthenticated";
    private static final String rememberMe = "rememberMe";

    private final ExpressionInterceptUrlRegistry REGISTRY = new ExpressionInterceptUrlRegistry();

    private SecurityExpressionHandler<FilterInvocation> expressionHandler;

    /**
     * Creates a new instance
     * @see HttpSecurity#authorizeRequests()
     */
    public ExpressionUrlAuthorizationConfigurer() {
    }

    public ExpressionInterceptUrlRegistry getRegistry() {
        return REGISTRY;
    }

    public class ExpressionInterceptUrlRegistry extends ExpressionUrlAuthorizationConfigurer<H>.AbstractInterceptUrlRegistry<ExpressionInterceptUrlRegistry,AuthorizedUrl> {

        @Override
        protected final AuthorizedUrl chainRequestMatchersInternal(List<RequestMatcher> requestMatchers) {
            return new AuthorizedUrl(requestMatchers);
        }


        /**
         * Allows customization of the {@link SecurityExpressionHandler} to be used. The default is {@link DefaultWebSecurityExpressionHandler}
         * 
         * <p> 允许使用SecurityExpressionHandler的自定义。 默认值为DefaultWebSecurityExpressionHandler
         *
         * @param expressionHandler the {@link SecurityExpressionHandler} to be used
         * 
         * <p> 要使用的SecurityExpressionHandler
         * 
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization.
         * 
         * <p> ExpressionUrlAuthorizationConfigurer，以进行进一步的自定义。
         */
        public ExpressionInterceptUrlRegistry expressionHandler(SecurityExpressionHandler<FilterInvocation> expressionHandler) {
            ExpressionUrlAuthorizationConfigurer.this.expressionHandler = expressionHandler;
            return this;
        }

        /**
         * Adds an {@link ObjectPostProcessor} for this class.
         *
         * <p> 为此类添加一个ObjectPostProcessor。
         * 
         * @param objectPostProcessor
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customizations
         * 
         * <p> ExpressionUrlAuthorizationConfigurer，以进行进一步的自定义。
         */
        public ExpressionInterceptUrlRegistry withObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
            addObjectPostProcessor(objectPostProcessor);
            return this;
        }

        public H and() {
            return ExpressionUrlAuthorizationConfigurer.this.and();
        }

    }


    /**
     * Allows registering multiple {@link RequestMatcher} instances to a collection of {@link ConfigAttribute} instances
     * 
     * <p> 允许将多个RequestMatcher实例注册到ConfigAttribute实例的集合
     *
     * @param requestMatchers the {@link RequestMatcher} instances to register to the {@link ConfigAttribute} instances
     * 
     * <p> RequestMatcher实例以注册到ConfigAttribute实例
     * 
     * @param configAttributes the {@link ConfigAttribute} to be mapped by the {@link RequestMatcher} instances
     * 
     * <p> 由RequestMatcher实例映射的ConfigAttribute
     */
    private void interceptUrl(Iterable<? extends RequestMatcher> requestMatchers, Collection<ConfigAttribute> configAttributes) {
        for(RequestMatcher requestMatcher : requestMatchers) {
            REGISTRY.addMapping(new AbstractConfigAttributeRequestMatcherRegistry.UrlMapping(requestMatcher, configAttributes));
        }
    }

    @Override
    @SuppressWarnings("rawtypes")
    final List<AccessDecisionVoter> getDecisionVoters(H http) {
        List<AccessDecisionVoter> decisionVoters = new ArrayList<AccessDecisionVoter>();
        WebExpressionVoter expressionVoter = new WebExpressionVoter();
        expressionVoter.setExpressionHandler(getExpressionHandler(http));
        decisionVoters.add(expressionVoter);
        return decisionVoters;
    }

    @Override
    final ExpressionBasedFilterInvocationSecurityMetadataSource createMetadataSource(H http) {
        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = REGISTRY.createRequestMap();
        if(requestMap.isEmpty()) {
            throw new IllegalStateException("At least one mapping is required (i.e. authorizeRequests().anyRequest.authenticated())");
        }
        return new ExpressionBasedFilterInvocationSecurityMetadataSource(requestMap, getExpressionHandler(http));
    }

    private SecurityExpressionHandler<FilterInvocation> getExpressionHandler(H http) {
        if(expressionHandler == null) {
            DefaultWebSecurityExpressionHandler defaultHandler = new DefaultWebSecurityExpressionHandler();
            AuthenticationTrustResolver trustResolver = http.getSharedObject(AuthenticationTrustResolver.class);
            if(trustResolver != null) {
                defaultHandler.setTrustResolver(trustResolver);
            }
            expressionHandler = postProcess(defaultHandler);
        }

        return expressionHandler;
    }

    private static String hasAnyRole(String... authorities) {
        String anyAuthorities = StringUtils.arrayToDelimitedString(authorities, "','ROLE_");
        return "hasAnyRole('ROLE_" + anyAuthorities + "')";
    }

    private static String hasRole(String role) {
        Assert.notNull(role, "role cannot be null");
        if (role.startsWith("ROLE_")) {
            throw new IllegalArgumentException("role should not start with 'ROLE_' since it is automatically inserted. Got '" + role + "'");
        }
        return "hasRole('ROLE_" + role + "')";
    }

    private static String hasAuthority(String authority) {
        return "hasAuthority('" + authority + "')";
    }

    private static String hasAnyAuthority(String... authorities) {
        String anyAuthorities = StringUtils.arrayToDelimitedString(authorities, "','");
        return "hasAnyAuthority('" + anyAuthorities + "')";
    }

    private static String hasIpAddress(String ipAddressExpression) {
        return "hasIpAddress('" + ipAddressExpression + "')";
    }

    public final class AuthorizedUrl {
        private List<RequestMatcher> requestMatchers;
        private boolean not;

        /**
         * Creates a new instance
         *
         * @param requestMatchers the {@link RequestMatcher} instances to map
         * 
         * <p> 要映射的RequestMatcher实例
         */
        private AuthorizedUrl(List<RequestMatcher> requestMatchers) {
            this.requestMatchers = requestMatchers;
        }

        /**
         * Negates the following expression.
         * 
         * <p> 取反以下表达式。
         *
         * @param role the role to require (i.e. USER, ADMIN, etc). Note, it should not start with "ROLE_" as
         *             this is automatically inserted.
         *             
         * <p> 所需的角色（即USER，ADMIN等）。 注意，它不能以“ ROLE_”开头，因为它是自动插入的。
         * 
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         * 
         * <p> ExpressionUrlAuthorizationConfigurer，以进行进一步的自定义
         */
        public AuthorizedUrl not() {
            this.not = true;
            return this;
        }

        /**
         * Shortcut for specifying URLs require a particular role. If you do not want to have "ROLE_" automatically
         * inserted see {@link #hasAuthority(String)}.
         * 
         * <p> 指定URL的快捷方式需要特定的角色。 如果您不想自动插入“ ROLE_”，请参见hasAuthority（String）。
         *
         * @param role the role to require (i.e. USER, ADMIN, etc). Note, it should not start with "ROLE_" as
         *             this is automatically inserted.
         *             
         * <p> 所需的角色（即USER，ADMIN等）。 注意，它不能以“ ROLE_”开头，因为它是自动插入的。
         * 
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         * 
         * <p> ExpressionUrlAuthorizationConfigurer，以进行进一步的自定义
         */
        public ExpressionInterceptUrlRegistry hasRole(String role) {
            return access(ExpressionUrlAuthorizationConfigurer.hasRole(role));
        }

        /**
         * Shortcut for specifying URLs require any of a number of roles. If you
         * do not want to have "ROLE_" automatically inserted see
         * {@link #hasAnyAuthority(String...)}
         * 
         * <p> 指定URL的快捷方式需要多个角色。 如果您不想自动插入“ ROLE_”，请参见hasAnyAuthority（String）
         *
         * @param roles
         *            the roles to require (i.e. USER, ADMIN, etc). Note, it
         *            should not start with "ROLE_" as this is automatically
         *            inserted.
         *            
         * <p> 需要的角色（即USER，ADMIN等）。 注意，它不能以“ ROLE_”开头，因为它是自动插入的。
         * 
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
         *         customization
         *         
         * <p> ExpressionUrlAuthorizationConfigurer，以进行进一步的自定义
         */
        public ExpressionInterceptUrlRegistry hasAnyRole(String... roles) {
            return access(ExpressionUrlAuthorizationConfigurer.hasAnyRole(roles));
        }

        /**
         * Specify that URLs require a particular authority.
         * 
         * <p> 指定URL需要特定的权限。
         *
         * @param authority the authority to require (i.e. ROLE_USER, ROLE_ADMIN, etc).
         * 
         * <p> 要求的权限（即ROLE_USER，ROLE_ADMIN等）。
         * 
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         * 
         * <p> ExpressionUrlAuthorizationConfigurer，以进行进一步的自定义
         */
        public ExpressionInterceptUrlRegistry hasAuthority(String authority) {
            return access(ExpressionUrlAuthorizationConfigurer.hasAuthority(authority));
        }

        /**
         * Specify that URLs requires any of a number authorities.
         * 
         * <p> 指定URL需要任何数字授权机构。
         *
         * @param authorities the requests require at least one of the authorities (i.e. "ROLE_USER","ROLE_ADMIN" would
         *                    mean either "ROLE_USER" or "ROLE_ADMIN" is required).
         *                    
         * <p> 这些请求至少需要一个权限（即“ ROLE_USER”，“ ROLE_ADMIN”意味着需要“ ROLE_USER”或“ ROLE_ADMIN”）。
         * 
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         * 
         * <p> ExpressionUrlAuthorizationConfigurer，以进行进一步的自定义
         */
        public ExpressionInterceptUrlRegistry hasAnyAuthority(String... authorities) {
            return access(ExpressionUrlAuthorizationConfigurer.hasAnyAuthority(authorities));
        }

        /**
         * Specify that URLs requires a specific IP Address or
         * <a href="http://forum.springsource.org/showthread.php?102783-How-to-use-hasIpAddress&p=343971#post343971">subnet</a>.
         * 
         * <p> 指定URL需要特定的IP地址或子网。
         *
         * @param ipaddressExpression the ipaddress (i.e. 192.168.1.79) or local subnet (i.e. 192.168.0/24)
         * 
         * <p> ipaddress（即192.168.1.79）或本地子网（即192.168.0 / 24）
         * 
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         * 
         * <p> ExpressionUrlAuthorizationConfigurer，以进行进一步的自定义
         */
        public ExpressionInterceptUrlRegistry hasIpAddress(String ipaddressExpression) {
            return access(ExpressionUrlAuthorizationConfigurer.hasIpAddress(ipaddressExpression));
        }

        /**
         * Specify that URLs are allowed by anyone.
         * 
         * <p> 指定任何人都允许使用URL。
         *
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         * 
         * <p> 返回：ExpressionUrlAuthorizationConfigurer，用于进一步定制
         */
        public ExpressionInterceptUrlRegistry permitAll() {
            return access(permitAll);
        }

        /**
         * Specify that URLs are allowed by anonymous users.
         * 
         * <p> 指定匿名用户允许使用URL。
         *
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         * 
         * <p> 返回：ExpressionUrlAuthorizationConfigurer，用于进一步定制
         */
        public ExpressionInterceptUrlRegistry anonymous() {
            return access(anonymous);
        }

        /**
         * Specify that URLs are allowed by users that have been remembered.
         * 
         * <p> 指定已记住的用户允许使用URL。
         *
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         * 
         * <p> ExpressionUrlAuthorizationConfigurer，以进行进一步的自定义
         * 
         * @see {@link RememberMeConfigurer}
         */
        public ExpressionInterceptUrlRegistry rememberMe() {
            return access(rememberMe);
        }

        /**
         * Specify that URLs are not allowed by anyone.
         * 
         * <p> 指定任何人都不允许使用URL。
         *
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         * 
         * <p> ExpressionUrlAuthorizationConfigurer，以进行进一步的自定义
         */
        public ExpressionInterceptUrlRegistry denyAll() {
            return access(denyAll);
        }

        /**
         * Specify that URLs are allowed by any authenticated user.
         * 
         * <p> 指定任何经过身份验证的用户都允许使用URL。
         *
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         * 
         * <p> ExpressionUrlAuthorizationConfigurer，以进行进一步的自定义
         */
        public ExpressionInterceptUrlRegistry authenticated() {
            return access(authenticated);
        }

        /**
         * Specify that URLs are allowed by users who have authenticated and were not "remembered".
         * 
         * <p> 指定已认证但未“记住”的用户允许使用URL。
         *
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         * 
         * <p> ExpressionUrlAuthorizationConfigurer，以进行进一步的自定义
         * 
         * @see {@link RememberMeConfigurer}
         */
        public ExpressionInterceptUrlRegistry fullyAuthenticated() {
            return access(fullyAuthenticated);
        }

        /**
         * Allows specifying that URLs are secured by an arbitrary expression
         * 
         * <p> 允许指定URL由任意表达式保护
         *
         * @param attribute the expression to secure the URLs (i.e. "hasRole('ROLE_USER') and hasRole('ROLE_SUPER')")
         * 
         * <p> 用于保护网址的表达式（即“ hasRole（'ROLE_USER'）和hasRole（'ROLE_SUPER'）“）
         * 
         * @return the {@link ExpressionUrlAuthorizationConfigurer} for further customization
         * 
         * <p> ExpressionUrlAuthorizationConfigurer，以进行进一步的自定义
         */
        public ExpressionInterceptUrlRegistry access(String attribute) {
            if(not) {
                attribute = "!" + attribute;
            }
            interceptUrl(requestMatchers, SecurityConfig.createList(attribute));
            return ExpressionUrlAuthorizationConfigurer.this.REGISTRY;
        }
    }
}