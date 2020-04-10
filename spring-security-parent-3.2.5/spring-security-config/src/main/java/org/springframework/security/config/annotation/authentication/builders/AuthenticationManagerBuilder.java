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
package org.springframework.security.config.annotation.authentication.builders;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.ldap.LdapAuthenticationProviderConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.JdbcUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.UserDetailsAwareConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;

/**
 * {@link SecurityBuilder} used to create an {@link AuthenticationManager}.
 * Allows for easily building in memory authentication, LDAP authentication,
 * JDBC based authentication, adding {@link UserDetailsService}, and adding
 * {@link AuthenticationProvider}'s.
 * 
 * <p> 用于创建AuthenticationManager的SecurityBuilder。 允许轻松构建内存身份验证，LDAP身份验证，
 * 基于JDBC的身份验证，添加UserDetailsService和添加AuthenticationProvider。
 * 
 *
 * @author Rob Winch
 * @since 3.2
 */
public class AuthenticationManagerBuilder extends AbstractConfiguredSecurityBuilder<AuthenticationManager, AuthenticationManagerBuilder> implements ProviderManagerBuilder<AuthenticationManagerBuilder> {
    private final Log logger = LogFactory.getLog(getClass());

    private AuthenticationManager parentAuthenticationManager;
    private List<AuthenticationProvider> authenticationProviders = new ArrayList<AuthenticationProvider>();
    private UserDetailsService defaultUserDetailsService;
    private Boolean eraseCredentials;
    private AuthenticationEventPublisher eventPublisher;

    /**
     * Creates a new instance
     * @param the {@link ObjectPostProcessor} instance to use.
     */
    public AuthenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor) {
        super(objectPostProcessor,true);
    }

    /**
     * Allows providing a parent {@link AuthenticationManager} that will be
     * tried if this {@link AuthenticationManager} was unable to attempt to
     * authenticate the provided {@link Authentication}.
     *
     * <p> 允许提供父AuthenticationManager，如果此AuthenticationManager无法尝试对提供的
     * Authentication进行身份验证，则可以尝试使用该方法。
     * 
     * @param authenticationManager
     *            the {@link AuthenticationManager} that should be used if the
     *            current {@link AuthenticationManager} was unable to attempt to
     *            authenticate the provided {@link Authentication}.
     *            
     * <p> 当前的AuthenticationManager无法尝试对提供的Authentication进行身份验证时应使用的AuthenticationManager。
     * 
     * @return the {@link AuthenticationManagerBuilder} for further adding types
     *         of authentication
     *         
     * <p> AuthenticationManagerBuilder，用于进一步添加身份验证类型
     */
    public AuthenticationManagerBuilder parentAuthenticationManager(
            AuthenticationManager authenticationManager) {
        if(authenticationManager instanceof ProviderManager) {
            eraseCredentials(((ProviderManager) authenticationManager).isEraseCredentialsAfterAuthentication());
        }
        this.parentAuthenticationManager = authenticationManager;
        return this;
    }

    /**
     * Sets the {@link AuthenticationEventPublisher}
     *
     * @param eventPublisher
     *            the {@link AuthenticationEventPublisher} to use
     * @return the {@link AuthenticationManagerBuilder} for further
     *         customizations
     */
    public AuthenticationManagerBuilder authenticationEventPublisher(AuthenticationEventPublisher eventPublisher) {
        Assert.notNull(eventPublisher, "AuthenticationEventPublisher cannot be null");
        this.eventPublisher = eventPublisher;
        return this;
    }

    /**
     *
     *
     * @param eraseCredentials
     *            true if {@link AuthenticationManager} should clear the
     *            credentials from the {@link Authentication} object after
     *            authenticating
     *            
     * <p> 如果AuthenticationManager在身份验证后应从Authentication对象清除凭据，则为true
     * 
     * @return the {@link AuthenticationManagerBuilder} for further customizations
     */
    public AuthenticationManagerBuilder eraseCredentials(boolean eraseCredentials) {
        this.eraseCredentials = eraseCredentials;
        return this;
    }


    /**
     * Add in memory authentication to the {@link AuthenticationManagerBuilder}
     * and return a {@link InMemoryUserDetailsManagerConfigurer} to
     * allow customization of the in memory authentication.
     * 
     * <p> 将内存身份验证添加到AuthenticationManagerBuilder中，并返回
     * InMemoryUserDetailsManagerConfigurer以允许自定义内存身份验证。
     *
     * <p>
     * This method also ensure that a {@link UserDetailsService} is available
     * for the {@link #getDefaultUserDetailsService()} method. Note that
     * additional {@link UserDetailsService}'s may override this
     * {@link UserDetailsService} as the default.
     * </p>
     * 
     * <p> 此方法还确保UserDetailsService可用于getDefaultUserDetailsService（）
     * 方法。 请注意，其他UserDetailsService可能会覆盖此UserDetailsService作为默认值。
     *
     * @return a {@link InMemoryUserDetailsManagerConfigurer} to allow
     *         customization of the in memory authentication
     *         
     * <p> InMemoryUserDetailsManagerConfigurer以允许自定义内存中身份验证
     * 
     * @throws Exception
     *             if an error occurs when adding the in memory authentication
     *             
     * <p> 如果添加内存中身份验证时发生错误
     */
    public InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> inMemoryAuthentication()
            throws Exception {
        return apply(new InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder>());
    }

    /**
     * Add JDBC authentication to the {@link AuthenticationManagerBuilder} and
     * return a {@link JdbcUserDetailsManagerConfigurer} to allow customization
     * of the JDBC authentication.
     * 
     * <p> 将JDBC身份验证添加到AuthenticationManagerBuilder中，
     * 并返回JdbcUserDetailsManagerConfigurer以允许自定义JDBC身份验证。
     *
     * <p>
     * When using with a persistent data store, it is best to add users external
     * of configuration using something like <a
     * href="http://flywaydb.org/">Flyway</a> or <a
     * href="http://www.liquibase.org/">Liquibase</a> to create the schema and
     * adding users to ensure these steps are only done once and that the
     * optimal SQL is used.
     * </p>
     * 
     * <p> 与持久性数据存储一起使用时，最好使用Flyway或Liquibase之类的东西在配置外部添加用户以创建架构，
     * 并添加用户以确保这些步骤仅执行一次并使用最佳SQL。
     *
     * <p>
     * This method also ensure that a {@link UserDetailsService} is available
     * for the {@link #getDefaultUserDetailsService()} method. Note that
     * additional {@link UserDetailsService}'s may override this
     * {@link UserDetailsService} as the default. See the <a href=
     * "http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#user-schema"
     * >User Schema</a> section of the reference for the default schema.
     * </p>
     * 
     * <p> 此方法还确保UserDetailsService可用于getDefaultUserDetailsService（）方法。 请注意，
     * 其他UserDetailsService可能会覆盖此UserDetailsService作为默认值。 有关默认架构，请参见参考资料的“用户架构”部分。
     *
     * @return a {@link JdbcUserDetailsManagerConfigurer} to allow customization
     *         of the JDBC authentication
     *         
     * <p> JdbcUserDetailsManagerConfigurer以允许定制JDBC身份验证
     * 
     * @throws Exception
     *             if an error occurs when adding the JDBC authentication
     *             
     * <p> 如果在添加JDBC身份验证时发生错误
     */
    public JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder> jdbcAuthentication()
            throws Exception {
        return apply(new JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder>());
    }

    /**
     * Add authentication based upon the custom {@link UserDetailsService} that
     * is passed in. It then returns a {@link DaoAuthenticationConfigurer} to
     * allow customization of the authentication.
     * 
     * <p> 根据传入的自定义UserDetailsService添加身份验证。然后，它返回DaoAuthenticationConfigurer以允许自定义身份验证。
     *
     * <p>
     * This method also ensure that the {@link UserDetailsService} is available
     * for the {@link #getDefaultUserDetailsService()} method. Note that
     * additional {@link UserDetailsService}'s may override this
     * {@link UserDetailsService} as the default.
     * 
     * <p> 此方法还确保UserDetailsService可用于getDefaultUserDetailsService（）方法。 
     * 请注意，其他UserDetailsService可能会覆盖此UserDetailsService作为默认值。
     * </p>
     *
     * @return a {@link DaoAuthenticationConfigurer} to allow customization
     *         of the DAO authentication
     *         
     * <p> DaoAuthenticationConfigurer以允许自定义DAO身份验证
     * 
     * @throws Exception
     *             if an error occurs when adding the {@link UserDetailsService}
     *             based authentication
     * 
     * <p> 如果添加基于UserDetailsService的身份验证时发生错误
     */
    public <T extends UserDetailsService> DaoAuthenticationConfigurer<AuthenticationManagerBuilder,T> userDetailsService(
            T userDetailsService) throws Exception {
        this.defaultUserDetailsService = userDetailsService;
        return apply(new DaoAuthenticationConfigurer<AuthenticationManagerBuilder,T>(userDetailsService));
    }

    /**
     * Add LDAP authentication to the {@link AuthenticationManagerBuilder} and
     * return a {@link LdapAuthenticationProviderConfigurer} to allow
     * customization of the LDAP authentication.
     * 
     * <p> 将LDAP身份验证添加到AuthenticationManagerBuilder中，并返回
     * LdapAuthenticationProviderConfigurer以允许自定义LDAP身份验证。
     *
     * <p>
     * This method <b>does NOT</b> ensure that a {@link UserDetailsService} is
     * available for the {@link #getDefaultUserDetailsService()} method.
     * </p>
     *
     * <p> 此方法不能确保UserDetailsService可用于getDefaultUserDetailsService（）方法。
     * 
     * @return a {@link LdapAuthenticationProviderConfigurer} to allow
     *         customization of the LDAP authentication
     *         
     * <p> LdapAuthenticationProviderConfigurer以允许自定义LDAP身份验证
     * 
     * @throws Exception
     *             if an error occurs when adding the LDAP authentication
     *             
     * <p> 如果添加LDAP认证时发生错误
     */
    public LdapAuthenticationProviderConfigurer<AuthenticationManagerBuilder> ldapAuthentication()
            throws Exception {
        return apply(new LdapAuthenticationProviderConfigurer<AuthenticationManagerBuilder>());
    }

    /**
     * Add authentication based upon the custom {@link AuthenticationProvider}
     * that is passed in. Since the {@link AuthenticationProvider}
     * implementation is unknown, all customizations must be done externally and
     * the {@link AuthenticationManagerBuilder} is returned immediately.
     * 
     * <p> 根据传入的自定义AuthenticationProvider添加身份验证。由于AuthenticationProvider
     * 实现是未知的，因此所有自定义操作都必须在外部完成，并且AuthenticationManagerBuilder会立即返回。
     *
     * <p>
     * This method <b>does NOT</b> ensure that the {@link UserDetailsService} is
     * available for the {@link #getDefaultUserDetailsService()} method.
     * </p>
     * 
     * <p> 此方法不能确保UserDetailsService可用于getDefaultUserDetailsService（）方法。
     *
     * @return a {@link AuthenticationManagerBuilder} to allow further authentication
     *         to be provided to the {@link AuthenticationManagerBuilder}
     *         
     * <p> AuthenticationManagerBuilder，以允许进一步的身份验证提供给AuthenticationManagerBuilder
     * 
     * @throws Exception
     *             if an error occurs when adding the {@link AuthenticationProvider}
     *             
     * <p> 如果添加AuthenticationProvider时发生错误
     */
    public AuthenticationManagerBuilder authenticationProvider(
            AuthenticationProvider authenticationProvider) {
        this.authenticationProviders.add(authenticationProvider);
        return this;
    }

    @Override
    protected ProviderManager performBuild() throws Exception {
        if(!isConfigured()) {
            logger.debug("No authenticationProviders and no parentAuthenticationManager defined. Returning null.");
            return null;
        }
        ProviderManager providerManager = new ProviderManager(authenticationProviders, parentAuthenticationManager);
        if(eraseCredentials != null) {
            providerManager.setEraseCredentialsAfterAuthentication(eraseCredentials);
        }
        if(eventPublisher != null) {
            providerManager.setAuthenticationEventPublisher(eventPublisher);
        }
        providerManager = postProcess(providerManager);
        return providerManager;
    }

    /**
     * Determines if the {@link AuthenticationManagerBuilder} is configured to
     * build a non null {@link AuthenticationManager}. This means that either a
     * non-null parent is specified or at least one
     * {@link AuthenticationProvider} has been specified.
     * 
     * <p> 确定是否将AuthenticationManagerBuilder配置为构建非null的AuthenticationManager。 
     * 这意味着指定了非空父级，或者已指定了至少一个AuthenticationProvider。
     *
     * <p>
     * When using {@link SecurityConfigurer} instances, the
     * {@link AuthenticationManagerBuilder} will not be configured until the
     * {@link SecurityConfigurer#configure(SecurityBuilder)} methods. This means
     * a {@link SecurityConfigurer} that is last could check this method and
     * provide a default configuration in the
     * {@link SecurityConfigurer#configure(SecurityBuilder)} method.
     * 
     * <p> 使用SecurityConfigurer实例时，直到配置SecurityConfigurer.configure（SecurityBuilder）方法时，
     * 才配置AuthenticationManagerBuilder。 这意味着最后一个SecurityConfigurer可以检查此方法，并在
     * SecurityConfigurer.configure（SecurityBuilder）方法中提供默认配置。
     *
     * @return
     */
    public boolean isConfigured() {
        return !authenticationProviders.isEmpty() || parentAuthenticationManager != null;
    }

    /**
     * Gets the default {@link UserDetailsService} for the
     * {@link AuthenticationManagerBuilder}. The result may be null in some
     * circumstances.
     * 
     * <p> 获取AuthenticationManagerBuilder的默认UserDetailsService。 在某些情况下，结果可能为null。
     *
     * @return the default {@link UserDetailsService} for the
     * {@link AuthenticationManagerBuilder}
     * 
     * <p> AuthenticationManagerBuilder的默认UserDetailsService
     */
    public UserDetailsService getDefaultUserDetailsService() {
        return this.defaultUserDetailsService;
    }

    /**
     * Captures the {@link UserDetailsService} from any {@link UserDetailsAwareConfigurer}.
     * 
     * <p> 从任何UserDetailsAwareConfigurer中捕获UserDetailsService。
     *
     * @param configurer the {@link UserDetailsAwareConfigurer} to capture the {@link UserDetailsService} from.
     * 
     * <p> UserDetailsAwareConfigurer来捕获UserDetailsService。
     * 
     * @return the {@link UserDetailsAwareConfigurer} for further customizations
     * 
     * <p> UserDetailsAwareConfigurer以进行进一步的自定义
     * 
     * @throws Exception if an error occurs
     */
    private <C extends UserDetailsAwareConfigurer<AuthenticationManagerBuilder,? extends UserDetailsService>> C apply(C configurer) throws Exception {
        this.defaultUserDetailsService = configurer.getUserDetailsService();
        return (C) super.apply(configurer);
    }
}