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
package org.springframework.security.config.annotation.web.builders;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.annotation.web.configurers.ChannelSecurityConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.annotation.web.configurers.JeeConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.PortMapperConfigurer;
import org.springframework.security.config.annotation.web.configurers.RememberMeConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.config.annotation.web.configurers.ServletApiConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.annotation.web.configurers.X509Configurer;
import org.springframework.security.config.annotation.web.configurers.openid.OpenIDLoginConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * A {@link HttpSecurity} is similar to Spring Security's XML <http> element in the namespace
 * configuration. It allows configuring web based security for specific http requests. By default
 * it will be applied to all requests, but can be restricted using {@link #requestMatcher(RequestMatcher)}
 * or other similar methods.
 * 
 * <p> HttpSecurity在名称空间配置中类似于Spring Security的XML元素。 它允许为特定的http请求配置基于Web的安全性。 
 * 默认情况下，它将应用于所有请求，但可以使用requestMatcher（RequestMatcher）或其他类似方法进行限制。
 *
 * <h2>Example Usage</h2>
 * 
 * <p> 用法示例
 *
 * The most basic form based configuration can be seen below. The configuration will require that any URL
 * that is requested will require a User with the role "ROLE_USER". It also defines an in memory authentication
 * scheme with a user that has the username "user", the password "password", and the role "ROLE_USER". For
 * additional examples, refer to the Java Doc of individual methods on {@link HttpSecurity}.
 *
 * <p> 以下是最基本的基于表单的配置。 该配置将要求所请求的任何URL都将需要一个角色为“ ROLE_USER”的用户。 它还使用用户名，用户名，
 * 密码“ password”和角色“ ROLE_USER”的用户定义了内存中身份验证方案。 有关其他示例，请参考HttpSecurity上各个方法的Java文档。
 * 
 * <pre>
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
 *
 *     &#064;Override
 *     protected void configure(HttpSecurity http) throws Exception {
 *         http
 *             .authorizeRequests()
 *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
 *                 .and()
 *             .formLogin();
 *     }
 *
 *     &#064;Override
 *     protected void configure(AuthenticationManagerBuilder auth) throws Exception {
 *         auth
 *              .inMemoryAuthentication()
 *                   .withUser(&quot;user&quot;)
 *                        .password(&quot;password&quot;)
 *                        .roles(&quot;USER&quot;);
 *     }
 * }
 * </pre>
 *
 * @author Rob Winch
 * @since 3.2
 * @see EnableWebSecurity
 */
public final class HttpSecurity extends AbstractConfiguredSecurityBuilder<DefaultSecurityFilterChain,HttpSecurity> implements SecurityBuilder<DefaultSecurityFilterChain>, HttpSecurityBuilder<HttpSecurity> {
    private final RequestMatcherConfigurer requestMatcherConfigurer = new RequestMatcherConfigurer();
    private List<Filter> filters =  new ArrayList<Filter>();
    private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;
    private FilterComparator comparitor = new FilterComparator();

    /**
     * Creates a new instance
     * @param objectPostProcessor the {@link ObjectPostProcessor} that should be used - 应该使用的ObjectPostProcessor
     * @param authenticationBuilder the {@link AuthenticationManagerBuilder} to use for additional updates
     * 
     * <p> AuthenticationManagerBuilder用于其他更新
     * 
     * @param sharedObjects the shared Objects to initialize the {@link HttpSecurity} with
     * 
     * <p> 共享对象以初始化HttpSecurity
     * 
     * @see WebSecurityConfiguration
     */
    public HttpSecurity(ObjectPostProcessor<Object> objectPostProcessor, AuthenticationManagerBuilder authenticationBuilder, Map<Class<Object>,Object> sharedObjects) {
        super(objectPostProcessor);
        Assert.notNull(authenticationBuilder, "authenticationBuilder cannot be null");
        setSharedObject(AuthenticationManagerBuilder.class, authenticationBuilder);
        for(Map.Entry<Class<Object>, Object> entry : sharedObjects.entrySet()) {
            setSharedObject(entry.getKey(), entry.getValue());
        }
    }

    /**
     * Allows configuring OpenID based authentication.
     *
     * <h2>Example Configurations</h2>
     *
     * A basic example accepting the defaults and not using attribute exchange:
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class OpenIDLoginConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) {
     *         http
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .openidLogin()
     *                 .permitAll();
     *     }
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     *         auth
     *                 .inMemoryAuthentication()
     *                     // the username must match the OpenID of the user you are
     *                     // logging in with
     *                     .withUser(&quot;https://www.google.com/accounts/o8/id?id=lmkCn9xzPdsxVwG7pjYMuDgNNdASFmobNkcRPaWU&quot;)
     *                         .password(&quot;password&quot;)
     *                         .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * A more advanced example demonstrating using attribute exchange and
     * providing a custom AuthenticationUserDetailsService that will make any
     * user that authenticates a valid user.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class OpenIDLoginConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) {
     *         http
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .openidLogin()
     *                 .loginPage(&quot;/login&quot;)
     *                 .permitAll()
     *                 .authenticationUserDetailsService(new AutoProvisioningUserDetailsService())
     *                     .attributeExchange(&quot;https://www.google.com/.*&quot;)
     *                         .attribute(&quot;email&quot;)
     *                             .type(&quot;http://axschema.org/contact/email&quot;)
     *                             .required(true)
     *                             .and()
     *                         .attribute(&quot;firstname&quot;)
     *                             .type(&quot;http://axschema.org/namePerson/first&quot;)
     *                             .required(true)
     *                             .and()
     *                         .attribute(&quot;lastname&quot;)
     *                             .type(&quot;http://axschema.org/namePerson/last&quot;)
     *                             .required(true)
     *                             .and()
     *                         .and()
     *                     .attributeExchange(&quot;.*yahoo.com.*&quot;)
     *                         .attribute(&quot;email&quot;)
     *                             .type(&quot;http://schema.openid.net/contact/email&quot;)
     *                             .required(true)
     *                             .and()
     *                         .attribute(&quot;fullname&quot;)
     *                             .type(&quot;http://axschema.org/namePerson&quot;)
     *                             .required(true)
     *                             .and()
     *                         .and()
     *                     .attributeExchange(&quot;.*myopenid.com.*&quot;)
     *                         .attribute(&quot;email&quot;)
     *                             .type(&quot;http://schema.openid.net/contact/email&quot;)
     *                             .required(true)
     *                             .and()
     *                         .attribute(&quot;fullname&quot;)
     *                             .type(&quot;http://schema.openid.net/namePerson&quot;)
     *                             .required(true);
     *     }
     * }
     *
     * public class AutoProvisioningUserDetailsService implements
     *         AuthenticationUserDetailsService&lt;OpenIDAuthenticationToken&gt; {
     *     public UserDetails loadUserDetails(OpenIDAuthenticationToken token) throws UsernameNotFoundException {
     *         return new User(token.getName(), &quot;NOTUSED&quot;, AuthorityUtils.createAuthorityList(&quot;ROLE_USER&quot;));
     *     }
     * }
     * </pre>
     *
     * @return the {@link OpenIDLoginConfigurer} for further customizations.
     *
     * @throws Exception
     * @see OpenIDLoginConfigurer
     */
    public OpenIDLoginConfigurer<HttpSecurity> openidLogin() throws Exception {
        return getOrApply(new OpenIDLoginConfigurer<HttpSecurity>());
    }

    /**
     * Adds the Security headers to the response. This is activated by default
     * when using {@link WebSecurityConfigurerAdapter}'s default constructor.
     * Only invoking the {@link #headers()} without invoking additional methods
     * on it, or accepting the default provided by
     * {@link WebSecurityConfigurerAdapter}, is the equivalent of:
     * 
     * <p> 将Security标头添加到响应中。 使用WebSecurityConfigurerAdapter的默认构造函数时，默认情况下将其激活。 
     * 仅调用headers（）而不调用其上的其他方法，或者接受WebSecurityConfigurerAdapter提供的默认值，等效于：
     * 
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .headers()
     *                 .contentTypeOptions();
     *                 .xssProtection()
     *                 .cacheControl()
     *                 .httpStrictTransportSecurity()
     *                 .frameOptions()
     *                 .and()
     *             ...;
     *     }
     * }
     * </pre>
     *
     * <p> You can disable the headers using the following:
     * 
     * <p> 您可以使用以下命令禁用标题：
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .headers().disable()
     *             ...;
     *     }
     * }
     * </pre>
     *
     * You can enable only a few of the headers by invoking the appropriate
     * methods on {@link #headers()} result. For example, the following will
     * enable {@link HeadersConfigurer#cacheControl()} and
     * {@link HeadersConfigurer#frameOptions()} only.
     * 
     * <p> 通过在headers（）结果上调用适当的方法，可以仅启用几个头。 例如，
     * 以下将仅启用HeadersConfigurer.cacheControl（）和HeadersConfigurer.frameOptions（）。
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     * 	&#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .headers()
     *                 .cacheControl()
     *                 .frameOptions()
     *                 .and()
     *             ...;
     *     }
     * }
     * </pre>
     *
     * @return
     * @throws Exception
     * @see {@link HeadersConfigurer}
     */
    public HeadersConfigurer<HttpSecurity> headers() throws Exception {
        return getOrApply(new HeadersConfigurer<HttpSecurity>());
    }

    /**
     * Allows configuring of Session Management.
     * 
     * <p> 允许配置会话管理。
     *
     * <h2>Example Configuration</h2>
     * 
     * <p> 配置示例
     *
     * The following configuration demonstrates how to enforce that only a
     * single instance of a user is authenticated at a time. If a user
     * authenticates with the username "user" without logging out and an attempt
     * to authenticate with "user" is made the first session will be forcibly
     * terminated and sent to the "/login?expired" URL.
     * 
     * <p> 以下配置演示了如何强制一次仅认证一个用户实例。 如果用户未注销而使用用户名“ user”进行身份验证，
     * 并且尝试使用“ user”进行身份验证，则第一个会话将被强制终止并发送到“ / login？expired” URL。
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class SessionManagementSecurityConfig extends
     *         WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeRequests()
     *                 .anyRequest().hasRole(&quot;USER&quot;)
     *                 .and()
     *            .formLogin()
     *                 .permitAll()
     *                 .and()
     *            .sessionManagement()
     *                 .maximumSessions(1)
     *                 .expiredUrl(&quot;/login?expired&quot;);
     *     }
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth.
     *             inMemoryAuthentication()
     *                 .withUser(&quot;user&quot;)
     *                     .password(&quot;password&quot;)
     *                     .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * <p> When using {@link SessionManagementConfigurer#maximumSessions(int)}, do
     * not forget to configure {@link HttpSessionEventPublisher} for the
     * application to ensure that expired sessions are cleaned up.
     * 
     * <p> 使用SessionManagementConfigurer.maximumSessions（int）时，请不要忘记为应用程序配置
     * HttpSessionEventPublisher，以确保清除过期的会话。 
     *
     * <p> In a web.xml this can be configured using the following:
     * 
     * <p> 在web.xml中，可以使用以下配置：
     *
     * <pre>
     * &lt;listener&gt;
     *      &ltlistener-class&gt;org.springframework.security.web.session.HttpSessionEventPublisher&lt;/listener-class&gt;
     * &lt/listener>
     * </pre>
     *
     * Alternatively,
     * {@link AbstractSecurityWebApplicationInitializer#enableHttpSessionEventPublisher()}
     * could return true.
     * 
     * <p> 或者，AbstractSecurityWebApplicationInitializer.enableHttpSessionEventPublisher（）可以返回true。
     *
     * @return the {@link SessionManagementConfigurer} for further
     *         customizations
     *         
     * <p> SessionManagementConfigurer以进行进一步的自定义
     * 
     * @throws Exception
     */
    public SessionManagementConfigurer<HttpSecurity> sessionManagement() throws Exception {
        return getOrApply(new SessionManagementConfigurer<HttpSecurity>());
    }

    /**
     * Allows configuring a {@link PortMapper} that is available from
     * {@link HttpSecurity#getSharedObject(Class)}. Other provided
     * {@link SecurityConfigurer} objects use this configured
     * {@link PortMapper} as a default {@link PortMapper} when redirecting from
     * HTTP to HTTPS or from HTTPS to HTTP (for example when used in combination
     * with {@link #requiresChannel()}. By default Spring Security uses a
     * {@link PortMapperImpl} which maps the HTTP port 8080 to the HTTPS port
     * 8443 and the HTTP port of 80 to the HTTPS port of 443.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration will ensure that redirects within Spring
     * Security from HTTP of a port of 9090 will redirect to HTTPS port of 9443
     * and the HTTP port of 80 to the HTTPS port of 443.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class PortMapperSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin()
     *                 .permitAll()
     *                 .and()
     *                 // Example portMapper() configuration
     *                 .portMapper()
     *                     .http(9090).mapsTo(9443)
     *                     .http(80).mapsTo(443);
     *     }
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     *         auth
     *             .inMemoryAuthentication()
     *                 .withUser(&quot;user&quot;)
     *                     .password(&quot;password&quot;)
     *                     .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * @return the {@link PortMapperConfigurer} for further customizations
     * @throws Exception
     * @see {@link #requiresChannel()}
     */
    public PortMapperConfigurer<HttpSecurity> portMapper() throws Exception {
        return getOrApply(new PortMapperConfigurer<HttpSecurity>());
    }

    /**
     * Configures container based based pre authentication. In this case,
     * authentication is managed by the Servlet Container.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration will use the principal found on the
     * {@link HttpServletRequest} and if the user is in the role "ROLE_USER" or
     * "ROLE_ADMIN" will add that to the resulting {@link Authentication}.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class JeeSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             // Example jee() configuration
     *             .jee()
     *                 .mappableRoles(&quot;ROLE_USER&quot;, &quot;ROLE_ADMIN&quot;);
     *     }
     * }
     * </pre>
     *
     * Developers wishing to use pre authentication with the container will need
     * to ensure their web.xml configures the security constraints. For example,
     * the web.xml (there is no equivalent Java based configuration supported by
     * the Servlet specification) might look like:
     *
     * <pre>
     * &lt;login-config&gt;
     *     &lt;auth-method&gt;FORM&lt;/auth-method&gt;
     *     &lt;form-login-config&gt;
     *         &lt;form-login-page&gt;/login&lt;/form-login-page&gt;
     *         &lt;form-error-page&gt;/login?error&lt;/form-error-page&gt;
     *     &lt;/form-login-config&gt;
     * &lt;/login-config&gt;
     *
     * &lt;security-role&gt;
     *     &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
     * &lt;/security-role&gt;
     * &lt;security-constraint&gt;
     *     &lt;web-resource-collection&gt;
     *     &lt;web-resource-name&gt;Public&lt;/web-resource-name&gt;
     *         &lt;description&gt;Matches unconstrained pages&lt;/description&gt;
     *         &lt;url-pattern&gt;/login&lt;/url-pattern&gt;
     *         &lt;url-pattern&gt;/logout&lt;/url-pattern&gt;
     *         &lt;url-pattern&gt;/resources/*&lt;/url-pattern&gt;
     *     &lt;/web-resource-collection&gt;
     * &lt;/security-constraint&gt;
     * &lt;security-constraint&gt;
     *     &lt;web-resource-collection&gt;
     *         &lt;web-resource-name&gt;Secured Areas&lt;/web-resource-name&gt;
     *         &lt;url-pattern&gt;/*&lt;/url-pattern&gt;
     *     &lt;/web-resource-collection&gt;
     *     &lt;auth-constraint&gt;
     *         &lt;role-name&gt;ROLE_USER&lt;/role-name&gt;
     *     &lt;/auth-constraint&gt;
     * &lt;/security-constraint&gt;
     * </pre>
     *
     * Last you will need to configure your container to contain the user with the
     * correct roles. This configuration is specific to the Servlet Container, so consult
     * your Servlet Container's documentation.
     *
     * @return the {@link JeeConfigurer} for further customizations
     * @throws Exception
     */
    public JeeConfigurer<HttpSecurity> jee() throws Exception {
        return getOrApply(new JeeConfigurer<HttpSecurity>());
    }

    /**
     * Configures X509 based pre authentication.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration will attempt to extract the username from
     * the X509 certificate. Remember that the Servlet Container will need to be
     * configured to request client certificates in order for this to work.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class X509SecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             // Example x509() configuration
     *             .x509();
     *     }
     * }
     * </pre>
     *
     * @return the {@link X509Configurer} for further customizations
     * @throws Exception
     */
    public X509Configurer<HttpSecurity> x509() throws Exception {
        return getOrApply(new X509Configurer<HttpSecurity>());
    }

    /**
     * Allows configuring of Remember Me authentication.
     *
     * <h2>Example Configuration</h2>
     *
     * The following configuration demonstrates how to allow token based remember me
     * authentication. Upon authenticating if the HTTP parameter named "remember-me" exists,
     * then the user will be remembered even after their {@link javax.servlet.http.HttpSession} expires.
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RememberMeSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;);
     *     }
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin()
     *                 .permitAll()
     *                 .and()
     *              // Example Remember Me Configuration
     *             .rememberMe();
     *     }
     * }
     * </pre>
     *
     * @return the {@link RememberMeConfigurer} for further customizations
     * @throws Exception
     */
    public RememberMeConfigurer<HttpSecurity> rememberMe() throws Exception {
        return getOrApply(new RememberMeConfigurer<HttpSecurity>());
    }


    /**
     * Allows restricting access based upon the {@link HttpServletRequest} using
     * 
     * <p> 允许使用HttpServletRequest限制访问
     *
     * <h2>Example Configurations</h2>
     * 
     * <p> 示例配置
     *
     * <p> The most basic example is to configure all URLs to require the role "ROLE_USER". The
     * configuration below requires authentication to every URL and will grant access to
     * both the user "admin" and "user".
     * 
     * <p> 最基本的示例是将所有URL配置为要求角色 "ROLE_USER"。 以下配置要求对每个URL进行身份验证，并将授予用户"admin"和"user"的访问权限。
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin();
     *     }
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;)
     *                        .and()
     *                   .withUser(&quot;adminr&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;ADMIN&quot;,&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * We can also configure multiple URLs. The configuration below requires authentication to every URL
     * and will grant access to URLs starting with /admin/ to only the "admin" user. All other URLs either
     * user can access.
     * 
     * <p> 我们还可以配置多个URL。 下面的配置要求对每个URL进行身份验证，并将仅对“ admin”用户授予对以/ admin /开头的URL的访问权限。 
     * 用户可以访问的所有其他URL。
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AuthorizeUrlsSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin();
     *     }
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;)
     *                        .and()
     *                   .withUser(&quot;adminr&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;ADMIN&quot;,&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * Note that the matchers are considered in order. Therefore, the following is invalid because the first
     * matcher matches every request and will never get to the second mapping:
     * 
     * <p> 请注意，匹配器按顺序考虑。 因此，以下内容无效，因为第一个匹配器会匹配每个请求，并且永远不会到达第二个映射：
     *
     * <pre>
     * http
     *     .authorizeRequests()
     *         .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *         .antMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
     * </pre>
     *
     * @see #requestMatcher(RequestMatcher)
     *
     * @return
     * @throws Exception
     */
    public ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests() throws Exception {
        return getOrApply(new ExpressionUrlAuthorizationConfigurer<HttpSecurity>()).getRegistry();
    }

    /**
     * Allows configuring the Request Cache. For example, a protected page (/protected) may be requested prior
     * to authentication. The application will redirect the user to a login page. After authentication, Spring
     * Security will redirect the user to the originally requested protected page (/protected). This is
     * automatically applied when using {@link WebSecurityConfigurerAdapter}.
     * 
     * <p> 允许配置请求缓存。 例如，可以在认证之前请求受保护的页面（/ protected）。 该应用程序会将用户重定向到登录页面。 经过身份验证后，
     * Spring Security会将用户重定向到最初请求的受保护页面（/ protected）。 
     * 使用WebSecurityConfigurerAdapter时将自动应用此功能。
     *
     * @return the {@link RequestCacheConfigurer} for further customizations
     * 
     * <p> RequestCacheConfigurer以进行进一步的自定义
     * 
     * @throws Exception
     */
    public RequestCacheConfigurer<HttpSecurity> requestCache() throws Exception {
        return getOrApply(new RequestCacheConfigurer<HttpSecurity>());
    }

    /**
     * Allows configuring exception handling. This is automatically applied when using
     * {@link WebSecurityConfigurerAdapter}.
     * 
     * <p> 允许配置异常处理。 使用WebSecurityConfigurerAdapter时将自动应用此功能。
     *
     * @return the {@link ExceptionHandlingConfigurer} for further customizations
     * 
     * <p> ExceptionHandlingConfigurer以进行进一步的自定义
     * 
     * @throws Exception
     */
    public ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling() throws Exception {
        return getOrApply(new ExceptionHandlingConfigurer<HttpSecurity>());
    }

    /**
     * Sets up management of the {@link SecurityContext} on the
     * {@link SecurityContextHolder} between {@link HttpServletRequest}'s. This is automatically
     * applied when using {@link WebSecurityConfigurerAdapter}.
     * 
     * <p> 在HttpServletRequest之间的SecurityContextHolder上设置SecurityContext的管理。 
     * 使用WebSecurityConfigurerAdapter时将自动应用此功能。
     *
     * @return the {@link SecurityContextConfigurer} for further customizations
     * 
     * <p> SecurityContextConfigurer以进行进一步的自定义
     * 
     * @throws Exception
     */
    public SecurityContextConfigurer<HttpSecurity> securityContext() throws Exception {
        return getOrApply(new SecurityContextConfigurer<HttpSecurity>());
    }

    /**
     * Integrates the {@link HttpServletRequest} methods with the values found
     * on the {@link SecurityContext}. This is automatically applied when using
     * {@link WebSecurityConfigurerAdapter}.
     * 
     * <p> 将HttpServletRequest方法与SecurityContext上找到的值集成在一起。 使用
     * WebSecurityConfigurerAdapter时将自动应用此功能。
     *
     * @return the {@link ServletApiConfigurer} for further customizations
     * 
     * <p> ServletApiConfigurer进行进一步的自定义
     * 
     * @throws Exception
     */
    public ServletApiConfigurer<HttpSecurity> servletApi() throws Exception {
        return getOrApply(new ServletApiConfigurer<HttpSecurity>());
    }


    /**
     * Adds CSRF support. This is activated by default when using
     * {@link WebSecurityConfigurerAdapter}'s default constructor. You can
     * disable it using:
     * 
     * <p> 添加了CSRF支持。 使用WebSecurityConfigurerAdapter的默认构造函数时，默认情况下将其激活。 您可以使用以下方式禁用它：
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class CsrfSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .csrf().disable()
     *             ...;
     *     }
     * }
     * </pre>
     *
     * @return the {@link ServletApiConfigurer} for further customizations
     * @throws Exception
     */
    public CsrfConfigurer<HttpSecurity> csrf() throws Exception {
        return getOrApply(new CsrfConfigurer<HttpSecurity>());
    }

    /**
     * Provides logout support. This is automatically applied when using
     * {@link WebSecurityConfigurerAdapter}. The default is that accessing
     * the URL "/logout" will log the user out by invalidating the HTTP Session,
     * cleaning up any {@link #rememberMe()} authentication that was configured,
     * clearing the {@link SecurityContextHolder}, and then redirect to
     * "/login?success".
     * 
     * <p> 提供注销支持。 使用WebSecurityConfigurerAdapter时将自动应用此功能。 默认设置是访问
     * URL“ / logout”将使HTTP会话无效，清理配置的所有RememberMe（）身份验证，清除
     * SecurityContextHolder，然后重定向到“ / login？success”，从而注销用户。
     *
     * <h2>Example Custom Configuration</h2>
     * 
     * <p> 定制配置示例
     *
     * The following customization to log out when the URL "/custom-logout" is
     * invoked. Log out will remove the cookie named "remove", not invalidate the
     * HttpSession, clear the SecurityContextHolder, and upon completion redirect
     * to "/logout-success".
     * 
     * <p> 以下自定义将在调用URL“ / custom-logout”时注销。 注销将删除名为“ remove”的cookie，不使HttpSession无效，
     * 清除SecurityContextHolder，并在完成后重定向到“ / logout-success”。
     * 
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class LogoutSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin()
     *                 .and()
     *             // sample logout customization
     *             .logout()
     *                 .logout()
     *                    .deleteCookies("remove")
     *                    .invalidateHttpSession(false)
     *                    .logoutUrl("/custom-logout")
     *                    .logoutSuccessUrl("/logout-success");
     *     }
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * @return
     * @throws Exception
     */
    public LogoutConfigurer<HttpSecurity> logout() throws Exception {
        return getOrApply(new LogoutConfigurer<HttpSecurity>());
    }

    /**
     * Allows configuring how an anonymous user is represented. This is automatically applied
     * when used in conjunction with {@link WebSecurityConfigurerAdapter}. By default anonymous
     * users will be represented with an {@link org.springframework.security.authentication.AnonymousAuthenticationToken} and contain the role
     * "ROLE_ANONYMOUS".
     * 
     * <p> 允许配置匿名用户的表示方式。 与WebSecurityConfigurerAdapter结合使用时，将自动应用此功能。 默认情况下，匿名用户将使用
     * org.springframework.security.authentication.AnonymousAuthenticationToken表示，并包含角色“ ROLE_ANONYMOUS”。
     *
     * <h2>Example Configuration</h2
     * 
     * <p> 配置示例
     *
     * <p> The following configuration demonstrates how to specify that anonymous users should contain
     * the role "ROLE_ANON" instead.
     *
     * <p> 以下配置演示了如何指定匿名用户应改为包含角色“ ROLE_ANON”。
     * 
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AnononymousSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin()
     *                 .and()
     *             // sample anonymous customization
     *             .anonymous()
     *                 .authorities("ROLE_ANON");
     *     }
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * <p> The following demonstrates how to represent anonymous users as null. Note that this can cause
     * {@link NullPointerException} in code that assumes anonymous authentication is enabled.
     * 
     * <p> 下面演示了如何将匿名用户表示为null。 请注意，这可能会在假定启用了匿名身份验证的代码中导致NullPointerException。
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class AnononymousSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin()
     *                 .and()
     *             // sample anonymous customization
     *             .anonymous()
     *                 .disabled();
     *     }
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * @return
     * @throws Exception
     */
    public AnonymousConfigurer<HttpSecurity> anonymous() throws Exception {
        return getOrApply(new AnonymousConfigurer<HttpSecurity>());
    }

    /**
     * Specifies to support form based authentication. If
     * {@link FormLoginConfigurer#loginPage(String)} is not specified a
     * default login page will be generated.
     * 
     * <p> 指定支持基于表单的身份验证。 如果未指定FormLoginConfigurer.loginPage（String），将生成默认登录页面。
     *
     * <h2>Example Configurations</h2>
     * 
     * <p> 示例配置
     *
     * The most basic configuration defaults to automatically generating a login
     * page at the URL "/login", redirecting to "/login?error" for
     * authentication failure. The details of the login page can be found on
     * {@link FormLoginConfigurer#loginPage(String)}
     * 
     * <p> 默认情况下，最基本的配置是在URL“ / login”处自动生成一个登录页面，并重定向到
     * “ / login？error”来进行身份验证失败。 登录页面的详细信息可以在FormLoginConfigurer.loginPage（String）上找到。
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin();
     *     }
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * The configuration below demonstrates customizing the defaults.
     * 
     * <p> 以下配置演示了自定义默认值。
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class FormLoginSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin()
     *                    .usernameParameter("j_username") // default is username
     *                    .passwordParameter("j_password") // default is password
     *                    .loginPage("/authentication/login") // default is /login with an HTTP get
     *                    .failureUrl("/authentication/login?failed") // default is /login?error
     *                    .loginProcessingUrl("/authentication/login/process"); // default is /login with an HTTP post
     *     }
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * @see FormLoginConfigurer#loginPage(String)
     *
     * @return
     * @throws Exception
     */
    public FormLoginConfigurer<HttpSecurity> formLogin() throws Exception {
        return getOrApply(new FormLoginConfigurer<HttpSecurity>());
    }

    /**
     * Configures channel security. In order for this configuration to be useful at least
     * one mapping to a required channel must be provided.
     * 
     * <p> 配置通道安全性。 为了使该配置有用，必须提供至少一个到所需通道的映射。
     *
     * <h2>Example Configuration</h2>
     * 
     * <p> 配置示例
     *
     * The example below demonstrates how to require HTTPs for every request. Only requiring HTTPS
     * for some requests is supported, but not recommended since an application that allows for HTTP
     * introduces many security vulnerabilities. For one such example, read about
     * <a href="http://en.wikipedia.org/wiki/Firesheep">Firesheep</a>.
     * 
     * <p> 下面的示例演示了如何为每个请求要求HTTP。 仅支持对某些请求使用HTTPS，但不建议这样做，因为允许HTTP的应用程序引入了许多安全漏洞。 
     * 有关此类示例，请阅读有关Firesheep的信息。
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class ChannelSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;)
     *                 .and()
     *             .formLogin()
     *                 .and()
     *             .requiresChannel()
     *                 .anyRequest().requiresSecure();
     *     }
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *              .inMemoryAuthentication()
     *                   .withUser(&quot;user&quot;)
     *                        .password(&quot;password&quot;)
     *                        .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     *
     * @return the {@link ChannelSecurityConfigurer} for further customizations
     * @throws Exception
     */
    public ChannelSecurityConfigurer<HttpSecurity>.ChannelRequestMatcherRegistry requiresChannel() throws Exception {
        return getOrApply(new ChannelSecurityConfigurer<HttpSecurity>()).getRegistry();
    }

    /**
     * Configures HTTP Basic authentication.
     * 
     * <p> 配置HTTP基本身份验证。
     *
     * <h2>Example Configuration</h2>
     * 
     * <p> 配置示例
     *
     * The example below demonstrates how to configure HTTP Basic authentication
     * for an application. The default realm is "Spring Security Application",
     * but can be customized using
     * {@link HttpBasicConfigurer#realmName(String)}.
     * 
     * <p> 下面的示例演示如何为应用程序配置HTTP基本身份验证。 默认领域是
     * “ Spring Security Application”，但可以使用HttpBasicConfigurer.realmName（String）进行自定义。
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class HttpBasicSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
     *                 .httpBasic();
     *     }
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *             .inMemoryAuthentication()
     *                 .withUser(&quot;user&quot;)
     *                     .password(&quot;password&quot;)
     *                     .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * @return the {@link HttpBasicConfigurer} for further customizations
     * @throws Exception
     */
    public HttpBasicConfigurer<HttpSecurity> httpBasic() throws Exception {
        return getOrApply(new HttpBasicConfigurer<HttpSecurity>());
    }

    @Override
    protected void beforeConfigure() throws Exception {
        setSharedObject(AuthenticationManager.class,getAuthenticationRegistry().build());
    }

    @Override
    protected DefaultSecurityFilterChain performBuild() throws Exception {
        Collections.sort(filters,comparitor);
        return new DefaultSecurityFilterChain(requestMatcher, filters);
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.web.HttpBuilder#authenticationProvider(org.springframework.security.authentication.AuthenticationProvider)
     */
    public HttpSecurity authenticationProvider(AuthenticationProvider authenticationProvider) {
        getAuthenticationRegistry().authenticationProvider(authenticationProvider);
        return this;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.web.HttpBuilder#userDetailsService(org.springframework.security.core.userdetails.UserDetailsService)
     */
    public HttpSecurity userDetailsService(UserDetailsService userDetailsService) throws Exception {
        getAuthenticationRegistry().userDetailsService(userDetailsService);
        return this;
    }

    private AuthenticationManagerBuilder getAuthenticationRegistry() {
        return getSharedObject(AuthenticationManagerBuilder.class);
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.web.HttpBuilder#addFilterAfter(javax.servlet.Filter, java.lang.Class)
     */
    public HttpSecurity addFilterAfter(Filter filter, Class<? extends Filter> afterFilter) {
        comparitor.registerAfter(filter.getClass(), afterFilter);
        return addFilter(filter);
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.web.HttpBuilder#addFilterBefore(javax.servlet.Filter, java.lang.Class)
     */
    public HttpSecurity addFilterBefore(Filter filter, Class<? extends Filter> beforeFilter) {
        comparitor.registerBefore(filter.getClass(), beforeFilter);
        return addFilter(filter);
    }

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.web.HttpBuilder#addFilter(javax.servlet.Filter)
     */
    public HttpSecurity addFilter(Filter filter) {
        Class<? extends Filter> filterClass = filter.getClass();
        if(!comparitor.isRegistered(filterClass)) {
            throw new IllegalArgumentException(
                    "The Filter class " + filterClass.getName()
                            + " does not have a registered order and cannot be added without a specified order. Consider using addFilterBefore or addFilterAfter instead.");
        }
        this.filters.add(filter);
        return this;
    }

    /**
     * Allows specifying which {@link HttpServletRequest} instances this
     * {@link HttpSecurity} will be invoked on.  This method allows for
     * easily invoking the {@link HttpSecurity} for multiple
     * different {@link RequestMatcher} instances. If only a single {@link RequestMatcher}
     * is necessary consider using {@link #antMatcher(String)},
     * {@link #regexMatcher(String)}, or {@link #requestMatcher(RequestMatcher)}.
     * 
     * <p> 允许指定将在其上调用此HttpSecurity的HttpServletRequest实例。 通过此方法，
     * 可以轻松地为多个不同的RequestMatcher实例调用HttpSecurity。 如果仅需要一个RequestMatcher，请考虑使用
     * antMatcher（String），regexMatcher（String）或requestMatcher（RequestMatcher）。
     * 
     * <p>
     * Invoking {@link #requestMatchers()} will override previous invocations of
     * {@link #requestMatchers()}, {@link #antMatcher(String)}, {@link #regexMatcher(String)},
     * and {@link #requestMatcher(RequestMatcher)}.
     * </p>
     * 
     * <p> 调用requestMatchers（）将覆盖先前对
     * requestMatchers（），antMatcher（String），regexMatcher（String）和requestMatcher（RequestMatcher）的调用。
     *
     * <h3>Example Configurations</h3>
     * 
     * <p> 示例配置
     *
     * The following configuration enables the {@link HttpSecurity} for URLs that
     * begin with "/api/" or "/oauth/".
     * 
     * <p> 以下配置为以“ / api /”或“ / oauth /”开头的URL启用HttpSecurity。
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .requestMatchers()
     *                 .antMatchers("/api/**","/oauth/**")
     *                 .and()
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
     *                 .httpBasic();
     *     }
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *             .inMemoryAuthentication()
     *                 .withUser(&quot;user&quot;)
     *                     .password(&quot;password&quot;)
     *                     .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * The configuration below is the same as the previous configuration.
     * 
     * <p> 以下配置与以前的配置相同。
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .requestMatchers()
     *                 .antMatchers("/api/**")
     *                 .antMatchers("/oauth/**")
     *                 .and()
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
     *                 .httpBasic();
     *     }
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *             .inMemoryAuthentication()
     *                 .withUser(&quot;user&quot;)
     *                     .password(&quot;password&quot;)
     *                     .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * The configuration below is also the same as the above configuration.
     * 
     * <p> 下面的配置也与上面的配置相同。
     *
     * <pre>
     * &#064;Configuration
     * &#064;EnableWebSecurity
     * public class RequestMatchersSecurityConfig extends WebSecurityConfigurerAdapter {
     *
     *     &#064;Override
     *     protected void configure(HttpSecurity http) throws Exception {
     *         http
     *             .requestMatchers()
     *                 .antMatchers("/api/**")
     *                 .and()
     *             .requestMatchers()
     *                 .antMatchers("/oauth/**")
     *                 .and()
     *             .authorizeRequests()
     *                 .antMatchers(&quot;/**&quot;).hasRole(&quot;USER&quot;).and()
     *                 .httpBasic();
     *     }
     *
     *     &#064;Override
     *     protected void configure(AuthenticationManagerBuilder auth)
     *             throws Exception {
     *         auth
     *             .inMemoryAuthentication()
     *                 .withUser(&quot;user&quot;)
     *                     .password(&quot;password&quot;)
     *                     .roles(&quot;USER&quot;);
     *     }
     * }
     * </pre>
     *
     * @return the {@link RequestMatcherConfigurer} for further customizations
     */
    public RequestMatcherConfigurer requestMatchers() {
        return requestMatcherConfigurer;
    }

    /**
     * Allows configuring the {@link HttpSecurity} to only be invoked when
     * matching the provided {@link RequestMatcher}. If more advanced configuration is
     * necessary, consider using {@link #requestMatchers()}.
     * 
     * <p> 允许将HttpSecurity配置为仅在与提供的RequestMatcher匹配时才被调用。 如果需要更高级的配置，请考虑使用requestMatchers（）。
     *
     * <p>
     * Invoking {@link #requestMatcher(RequestMatcher)} will override previous invocations of
     * {@link #requestMatchers()}, {@link #antMatcher(String)}, {@link #regexMatcher(String)},
     * and {@link #requestMatcher(RequestMatcher)}.
     * </p>
     * 
     * <p> 调用requestMatcher（RequestMatcher）将覆盖先前对requestMatchers（），antMatcher（String），
     * regexMatcher（String）和requestMatcher（RequestMatcher）的调用。
     *
     * @param requestMatcher the {@link RequestMatcher} to use (i.e. new AntPathRequestMatcher("/admin/**","GET") )
     * 
     * <p> 要使用的RequestMatcher（即新的AntPathRequestMatcher（“ / admin / **”，“ GET”））
     * 
     * @return the {@link HttpSecurity} for further customizations
     * 
     * <p> HttpSecurity进行进一步的自定义
     * 
     * @see #requestMatchers()
     * @see #antMatcher(String)
     * @see #regexMatcher(String)
     */
    public HttpSecurity requestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
        return this;
    }

    /**
     * Allows configuring the {@link HttpSecurity} to only be invoked when
     * matching the provided ant pattern. If more advanced configuration is
     * necessary, consider using {@link #requestMatchers()} or
     * {@link #requestMatcher(RequestMatcher)}.
     * 
     * <p> 允许将HttpSecurity配置为仅在匹配提供的ant模式时被调用。 如果需要更高级的配置，
     * 请考虑使用requestMatchers（）或requestMatcher（RequestMatcher）。
     *
     * <p>
     * Invoking {@link #antMatcher(String)} will override previous invocations of
     * {@link #requestMatchers()}, {@link #antMatcher(String)}, {@link #regexMatcher(String)},
     * and {@link #requestMatcher(RequestMatcher)}.
     * </p>
     * 
     * <p> 调用antMatcher（String）将覆盖先前对requestMatchers（），antMatcher（String），
     * regexMatcher（String）和requestMatcher（RequestMatcher）的调用。
     *
     * @param antPattern the Ant Pattern to match on (i.e. "/admin/**")
     * 
     * <p> 匹配的蚂蚁模式（即“ / admin / **”）
     * 
     * @return the {@link HttpSecurity} for further customizations
     * 
     * <p> HttpSecurity进行进一步的自定义
     * 
     * @see AntPathRequestMatcher
     */
    public HttpSecurity antMatcher(String antPattern) {
        return requestMatcher(new AntPathRequestMatcher(antPattern));
    }

    /**
     * Allows configuring the {@link HttpSecurity} to only be invoked when
     * matching the provided regex pattern. If more advanced configuration is
     * necessary, consider using {@link #requestMatchers()} or
     * {@link #requestMatcher(RequestMatcher)}.
     * 
     * <p> 允许将HttpSecurity配置为仅在匹配提供的正则表达式模式时被调用。 如果需要更高级的配置，
     * 请考虑使用requestMatchers（）或requestMatcher（RequestMatcher）。
     *
     * <p>
     * Invoking {@link #regexMatcher(String)} will override previous invocations of
     * {@link #requestMatchers()}, {@link #antMatcher(String)}, {@link #regexMatcher(String)},
     * and {@link #requestMatcher(RequestMatcher)}.
     * </p>
     * 
     * <p> 调用regexMatcher（String）将覆盖先前对requestMatchers（），antMatcher（String），
     * regexMatcher（String）和requestMatcher（RequestMatcher）的调用。
     *
     * @param pattern the Regular Expression to match on (i.e. "/admin/.+")
     * 
     * <p> 要匹配的正则表达式（即“ /admin/.+”）
     * 
     * @return the {@link HttpSecurity} for further customizations
     * 
     * <p> HttpSecurity进行进一步的自定义
     * 
     * @see RegexRequestMatcher
     */
    public HttpSecurity regexMatcher(String pattern) {
        return requestMatcher(new RegexRequestMatcher(pattern, null));
    }

    /**
     * Allows mapping HTTP requests that this {@link HttpSecurity} will be used for
     * 
     * <p> 允许映射此HttpSecurity将用于的HTTP请求
     *
     * @author Rob Winch
     * @since 3.2
     */
    public final class RequestMatcherConfigurer extends AbstractRequestMatcherRegistry<RequestMatcherConfigurer> {

        protected RequestMatcherConfigurer chainRequestMatchers(List<RequestMatcher> requestMatchers) {
            requestMatcher(new OrRequestMatcher(requestMatchers));
            return this;
        }

        /**
         * Return the {@link HttpSecurity} for further customizations
         * 
         * <p> 返回HttpSecurity进行进一步的自定义
         *
         * @return the {@link HttpSecurity} for further customizations
         */
        public HttpSecurity and() {
            return HttpSecurity.this;
        }

        private RequestMatcherConfigurer(){}
    }

    /**
     * If the {@link SecurityConfigurer} has already been specified get the original, otherwise apply the new {@link SecurityConfigurerAdapter}.
     *
     * <p> 如果已经指定了SecurityConfigurer，则获取原始文件，否则应用新的SecurityConfigurerAdapter。
     * 
     * @param configurer the {@link SecurityConfigurer} to apply if one is not found for this {@link SecurityConfigurer} class.
     * 
     * <p> 如果找不到此SecurityConfigurer类之一，则应用SecurityConfigurer。
     * 
     * @return the current {@link SecurityConfigurer} for the configurer passed in
     * 
     * <p> 传入的配置程序的当前SecurityConfigurer
     * 
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    private <C extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> C getOrApply(C configurer)
            throws Exception {
        C existingConfig = (C) getConfigurer(configurer.getClass());
        if(existingConfig != null) {
            return existingConfig;
        }
        return apply(configurer);
    }
}