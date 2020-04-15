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
package org.springframework.security.config.annotation.web.configuration;


import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.aop.TargetSource;
import org.springframework.aop.framework.Advised;
import org.springframework.aop.target.LazyInitTargetSource;
import org.springframework.beans.FatalBeanException;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 * Provides a convenient base class for creating a {@link WebSecurityConfigurer}
 * instance. The implementation allows customization by overriding methods.
 * 
 * <p> 提供用于创建WebSecurityConfigurer实例的便捷基类。 该实现允许通过覆盖方法进行自定义。
 *
 * @see EnableWebSecurity
 *
 * @author Rob Winch
 */
@Order(100)
public abstract class WebSecurityConfigurerAdapter implements WebSecurityConfigurer<WebSecurity> {
    private final Log logger = LogFactory.getLog(WebSecurityConfigurerAdapter.class);

    private ApplicationContext context;

    private ContentNegotiationStrategy contentNegotiationStrategy = new HeaderContentNegotiationStrategy();

    private ObjectPostProcessor<Object> objectPostProcessor = new ObjectPostProcessor<Object>() {
        public <T> T postProcess(T object) {
            throw new IllegalStateException(ObjectPostProcessor.class.getName()+ " is a required bean. Ensure you have used @EnableWebSecurity and @Configuration");
        }
    };

    private AuthenticationConfiguration authenticationConfiguration;
    private AuthenticationManagerBuilder authenticationBuilder;
    private AuthenticationManagerBuilder localConfigureAuthenticationBldr;
    private boolean disableLocalConfigureAuthenticationBldr;
    private boolean authenticationManagerInitialized;
    private AuthenticationManager authenticationManager;
    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private HttpSecurity http;
    private boolean disableDefaults;

    /**
     * Creates an instance with the default configuration enabled.
     * 
     * <p> 创建一个启用默认配置的实例。
     */
    protected WebSecurityConfigurerAdapter() {
        this(false);
    }

    /**
     * Creates an instance which allows specifying if the default configuration
     * should be enabled. Disabling the default configuration should be
     * considered more advanced usage as it requires more understanding of how
     * the framework is implemented.
     * 
     * <p> 创建一个实例，该实例允许指定是否应启用默认配置。 禁用默认配置应该被认为是更高级的用法，因为它需要对框架的实现方式有更多的了解。
     *
     * @param disableDefaults
     *            true if the default configuration should be enabled, else
     *            false
     *            
     * <p> 如果应启用默认配置，则为true，否则为false
     */
    protected WebSecurityConfigurerAdapter(boolean disableDefaults) {
        this.disableDefaults = disableDefaults;
    }

    /**
     * Used by the default implementation of {@link #authenticationManager()} to
     * attempt to obtain an {@link AuthenticationManager}. If overridden, the
     * {@link AuthenticationManagerBuilder} should be used to specify the
     * {@link AuthenticationManager}.
     * 
     * <p> 由authenticationManager（）的默认实现使用，以尝试获取AuthenticationManager。 如果被覆盖，
     * 则应使用AuthenticationManagerBuilder指定AuthenticationManager。
     *
     * <p>
     * The {@link #authenticationManagerBean()} method can be used to expose the
     * resulting {@link AuthenticationManager} as a Bean. The
     * {@link #userDetailsServiceBean()} can be used to expose the last
     * populated {@link UserDetailsService} that is created with the
     * {@link AuthenticationManagerBuilder} as a Bean. The
     * {@link UserDetailsService} will also automatically be populated on
     * {@link HttpSecurity#getSharedObject(Class)} for use with other
     * {@link SecurityContextConfigurer} (i.e. RememberMeConfigurer )
     * </p>
     * 
     * <p> authenticationManagerBean（）方法可用于将生成的AuthenticationManager公开为Bean。 
     * userDetailsServiceBean（）可用于公开使用AuthenticationManagerBuilder作为Bean
     * 创建的最后填充的UserDetailsService。 UserDetailsService也将自动填充在
     * HttpSecurity.getSharedObject（Class）上，以与其他
     * SecurityContextConfigurer（即RememberMeConfigurer）一起使用
     *
     * <p>
     * For example, the following configuration could be used to register in
     * memory authentication that exposes an in memory
     * {@link UserDetailsService}:
     * </p>
     *
     * <p> 例如，以下配置可用于在内存身份验证中注册，该身份验证公开内存中的UserDetailsService：
     * 
     * <pre>
     * &#064;Override
     * protected void configure(AuthenticationManagerBuilder auth) {
     *     auth
     *         // enable in memory based authentication with a user named
     *         // &quot;user&quot; and &quot;admin&quot;
     *         .inMemoryAuthentication()
     *             .withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;).and()
     *             .withUser(&quot;admin&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;, &quot;ADMIN&quot;);
     * }
     *
     * // Expose the UserDetailsService as a Bean
     * &#064;Bean
     * &#064;Override
     * public UserDetailsService userDetailsServiceBean() throws Exception {
     *     return super.userDetailsServiceBean();
     * }
     *
     * </pre>
     *
     * @param auth
     *            the {@link AuthenticationManagerBuilder} to use
     * @throws Exception
     */
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        this.disableLocalConfigureAuthenticationBldr = true;
    }

    /**
     * Creates the {@link HttpSecurity} or returns the current instance
     * 
     * <p> 创建HttpSecurity或返回当前实例
     *
     * @return the {@link HttpSecurity}
     * @throws Exception
     */
    protected final HttpSecurity getHttp() throws Exception {
        if(http != null) {
            return http;
        }

        DefaultAuthenticationEventPublisher eventPublisher = objectPostProcessor.postProcess(new DefaultAuthenticationEventPublisher());
        localConfigureAuthenticationBldr.authenticationEventPublisher(eventPublisher);

        AuthenticationManager authenticationManager = authenticationManager();
        authenticationBuilder.parentAuthenticationManager(authenticationManager);
        http = new HttpSecurity(objectPostProcessor,authenticationBuilder, localConfigureAuthenticationBldr.getSharedObjects());
        http.setSharedObject(UserDetailsService.class, userDetailsService());
        http.setSharedObject(ApplicationContext.class, context);
        http.setSharedObject(ContentNegotiationStrategy.class, contentNegotiationStrategy);
        http.setSharedObject(AuthenticationTrustResolver.class, trustResolver);
        if(!disableDefaults) { //初始化security 默认的配置
            http
                .csrf().and()
                .addFilter(new WebAsyncManagerIntegrationFilter())
                .exceptionHandling().and()
                .headers().and()
                .sessionManagement().and()
                .securityContext().and()
                .requestCache().and()
                .anonymous().and()
                .servletApi().and()
                .apply(new DefaultLoginPageConfigurer<HttpSecurity>()).and()
                .logout();
        }
        configure(http);// 初始化用户自定义的security相关配置
        return http;
    }

    /**
     * Override this method to expose the {@link AuthenticationManager} from
     * {@link #configure(AuthenticationManagerBuilder)} to be exposed as
     * a Bean. For example:
     *
     * <pre>
     * &#064;Bean(name name="myAuthenticationManager")
     * &#064;Override
     * public AuthenticationManager authenticationManagerBean() throws Exception {
     *     return super.authenticationManagerBean();
     * }
     * </pre>
     *
     * @return the {@link AuthenticationManager}
     * @throws Exception
     */
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return new AuthenticationManagerDelegator(authenticationBuilder, context);
    }

    /**
     * Gets the {@link AuthenticationManager} to use. The default strategy is if
     * {@link #configure(AuthenticationManagerBuilder)} method is
     * overridden to use the {@link AuthenticationManagerBuilder} that was passed in.
     * Otherwise, autowire the {@link AuthenticationManager} by type.
     * 
     * <p> 获取要使用的AuthenticationManager。 缺省策略是是否重写configure（AuthenticationManagerBuilder）
     * 方法以使用传入的AuthenticationManagerBuilder。否则，请按类型自动连接AuthenticationManager。
     *
     * @return
     * @throws Exception
     */
    protected AuthenticationManager authenticationManager() throws Exception {
        if(!authenticationManagerInitialized) {
            configure(localConfigureAuthenticationBldr);
            if(disableLocalConfigureAuthenticationBldr) {
                authenticationManager = authenticationConfiguration.getAuthenticationManager();
            } else {
                authenticationManager = localConfigureAuthenticationBldr.build();
            }
            authenticationManagerInitialized = true;
        }
        return authenticationManager;
    }

    /**
     * Override this method to expose a {@link UserDetailsService} created from
     * {@link #configure(AuthenticationManagerBuilder)} as a bean. In
     * general only the following override should be done of this method:
     * 
     * <p> 重写此方法，以将通过configure（AuthenticationManagerBuilder）创建的
     * UserDetailsService公开为Bean。 通常，此方法仅应执行以下重写：
     *
     * <pre>
     * &#064;Bean(name = "myUserDetailsService") // any or no name specified is allowed
     * &#064;Override
     * public UserDetailsService userDetailsServiceBean() throws Exception {
     *     return super.userDetailsServiceBean();
     * }
     * </pre>
     *
     * To change the instance returned, developers should change
     * {@link #userDetailsService()} instead
     * @return
     * @throws Exception
     * @see {@link #userDetailsService()}
     */
    public UserDetailsService userDetailsServiceBean() throws Exception {
        AuthenticationManagerBuilder globalAuthBuilder = context.getBean(AuthenticationManagerBuilder.class);
        return new UserDetailsServiceDelegator(Arrays.asList(localConfigureAuthenticationBldr, globalAuthBuilder));
    }

    /**
     * Allows modifying and accessing the {@link UserDetailsService} from
     * {@link #userDetailsServiceBean()()} without interacting with the
     * {@link ApplicationContext}. Developers should override this method when
     * changing the instance of {@link #userDetailsServiceBean()}.
     * 
     * <p> 允许从#userDetailsServiceBean（）（）修改和访问UserDetailsService，
     * 而无需与ApplicationContext进行交互。 当更改userDetailsServiceBean（）的实例时，开发人员应重写此方法。
     *
     * @return
     */
    protected UserDetailsService userDetailsService() {
        AuthenticationManagerBuilder globalAuthBuilder = context.getBean(AuthenticationManagerBuilder.class);
        return new UserDetailsServiceDelegator(Arrays.asList(localConfigureAuthenticationBldr, globalAuthBuilder));
    }

    public void init(final WebSecurity web) throws Exception {
        final HttpSecurity http = getHttp(); //初始化系统默认的security配置和用户自定义的security配置
        web
            .addSecurityFilterChainBuilder(http) //向HttpSecurity中添加securityFilter链中,
            .postBuildAction(new Runnable() {
                public void run() {
                    FilterSecurityInterceptor securityInterceptor = http.getSharedObject(FilterSecurityInterceptor.class);
                    web.securityInterceptor(securityInterceptor);
                }
            });
    }

    /**
     * Override this method to configure {@link WebSecurity}. For
     * example, if you wish to ignore certain requests.
     * 
     * <p> 重写此方法以配置WebSecurity。 例如，如果您希望忽略某些请求。
     */
    public void configure(WebSecurity web) throws Exception {
    }

    /**
     * Override this method to configure the {@link HttpSecurity}.
     * Typically subclasses should not invoke this method by calling super
     * as it may override their configuration. The default configuration is:
     * 
     * <p> 重写此方法以配置HttpSecurity。 通常，子类不应通过调用super来调用此方法，因为它可能会覆盖其配置。 默认配置为：
     *
     * <pre>
     * http
     *     .authorizeRequests()
     *         .anyRequest().authenticated().and()
     *     .formLogin().and()
     *     .httpBasic();
     * </pre>
     *
     * @param http
     *            the {@link HttpSecurity} to modify
     * @throws Exception
     *             if an error occurs
     */
    protected void configure(HttpSecurity http) throws Exception {
        logger.debug("Using default configure(HttpSecurity). If subclassed this will potentially override subclass configure(HttpSecurity).");

        http
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .formLogin().and()
            .httpBasic();
    }

    @Autowired
    public void setApplicationContext(ApplicationContext context) {
        this.context = context;
    }

    @Autowired(required=false)
    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        this.trustResolver = trustResolver;
    }

    @Autowired(required=false)
    public void setContentNegotationStrategy(ContentNegotiationStrategy contentNegotiationStrategy) {
        this.contentNegotiationStrategy = contentNegotiationStrategy;
    }

    @Autowired
    public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
        this.objectPostProcessor = objectPostProcessor;

        authenticationBuilder = new AuthenticationManagerBuilder(objectPostProcessor);
        localConfigureAuthenticationBldr = new AuthenticationManagerBuilder(objectPostProcessor) {
            @Override
            public AuthenticationManagerBuilder eraseCredentials(boolean eraseCredentials) {
                authenticationBuilder.eraseCredentials(eraseCredentials);
                return super.eraseCredentials(eraseCredentials);
            }

        };
    }

    @Autowired
    public void setAuthenticationConfiguration(AuthenticationConfiguration authenticationConfiguration) {
        this.authenticationConfiguration = authenticationConfiguration;
    }

    /**
     * Delays the use of the {@link UserDetailsService} from the
     * {@link AuthenticationManagerBuilder} to ensure that it has been fully
     * configured.
     * 
     * <p> 延迟使用AuthenticationManagerBuilder中的UserDetailsService以确保已完全配置它。
     *
     * @author Rob Winch
     * @since 3.2
     */
    static final class UserDetailsServiceDelegator implements UserDetailsService {
        private List<AuthenticationManagerBuilder> delegateBuilders;
        private UserDetailsService delegate;
        private final Object delegateMonitor = new Object();

        UserDetailsServiceDelegator(List<AuthenticationManagerBuilder> delegateBuilders) {
            if(delegateBuilders.contains(null)) {
                throw new IllegalArgumentException("delegateBuilders cannot contain null values. Got " + delegateBuilders);
            }
            this.delegateBuilders = delegateBuilders;
        }

        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            if(delegate != null) {
                return delegate.loadUserByUsername(username);
            }

            synchronized(delegateMonitor) {
                if (delegate == null) {
                    for(AuthenticationManagerBuilder delegateBuilder : delegateBuilders) {
                        delegate = delegateBuilder.getDefaultUserDetailsService();
                        if(delegate != null) {
                            break;
                        }
                    }

                    if(delegate == null) {
                        throw new IllegalStateException("UserDetailsService is required.");
                    }
                    this.delegateBuilders = null;
                }
            }

            return delegate.loadUserByUsername(username);
        }
    }


    /**
     * Delays the use of the {@link AuthenticationManager} build from the
     * {@link AuthenticationManagerBuilder} to ensure that it has been fully
     * configured.
     * 
     * <p> 从AuthenticationManagerBuilder延迟使用AuthenticationManager构建以确保已完全配置。
     *
     * @author Rob Winch
     * @since 3.2
     */
    static final class AuthenticationManagerDelegator implements AuthenticationManager {
        private AuthenticationManagerBuilder delegateBuilder;
        private AuthenticationManager delegate;
        private final Object delegateMonitor = new Object();
        private Set<String> beanNames;

        AuthenticationManagerDelegator(AuthenticationManagerBuilder delegateBuilder, ApplicationContext context) {
            Assert.notNull(delegateBuilder,"delegateBuilder cannot be null");
            Field parentAuthMgrField = ReflectionUtils.findField(AuthenticationManagerBuilder.class, "parentAuthenticationManager");
            ReflectionUtils.makeAccessible(parentAuthMgrField);
            beanNames = getAuthenticationManagerBeanNames(context);
            validateBeanCycle(ReflectionUtils.getField(parentAuthMgrField, delegateBuilder), beanNames);
            this.delegateBuilder = delegateBuilder;
        }

        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            if(delegate != null) {
                return delegate.authenticate(authentication);
            }

            synchronized(delegateMonitor) {
                if (delegate == null) {
                    delegate = this.delegateBuilder.getObject();
                    this.delegateBuilder = null;
                }
            }

            return delegate.authenticate(authentication);
        }

        private static Set<String> getAuthenticationManagerBeanNames(ApplicationContext applicationContext) {
             String[] beanNamesForType = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(applicationContext, AuthenticationManager.class);
             return new HashSet<String>(Arrays.asList(beanNamesForType));
        }

        private static void validateBeanCycle(Object auth, Set<String> beanNames) {
            if(auth != null && !beanNames.isEmpty()) {
                if(auth instanceof Advised){
                    Advised advised = (Advised) auth;
                    TargetSource targetSource = advised.getTargetSource();
                    if(targetSource instanceof LazyInitTargetSource) {
                        LazyInitTargetSource lits = (LazyInitTargetSource) targetSource;
                        if(beanNames.contains(lits.getTargetBeanName())) {
                            throw new FatalBeanException("A dependency cycle was detected when trying to resolve the AuthenticationManager. Please ensure you have configured authentication.");
                        }
                    }
                }
                beanNames = Collections.emptySet();
            }
        }
    }
}