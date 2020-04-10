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
package org.springframework.security.config.annotation.authentication.configurers.provisioning;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.UserDetailsServiceConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.util.Assert;

/**
 * Base class for populating an
 * {@link org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder} with a
 * {@link UserDetailsManager}.
 * 
 * <p> 使用UserDetailsManager填充
 * org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder的基类。
 *
 * @param <B> the type of the {@link SecurityBuilder} that is being configured
 * 
 * <p> 正在配置的SecurityBuilder的类型
 * 
 * @param <C> the type of {@link UserDetailsManagerConfigurer}
 * 
 * <p> UserDetailsManagerConfigurer的类型
 *
 * @author Rob Winch
 * @since 3.2
 */
public class UserDetailsManagerConfigurer<B extends ProviderManagerBuilder<B>, C extends UserDetailsManagerConfigurer<B,C>> extends
        UserDetailsServiceConfigurer<B,C,UserDetailsManager> {

    private final List<UserDetailsBuilder> userBuilders = new ArrayList<UserDetailsBuilder>();

    protected UserDetailsManagerConfigurer(UserDetailsManager userDetailsManager) {
        super(userDetailsManager);
    }

    /**
     * Populates the users that have been added.
     * 
     * <p> 填充已添加的用户。
     *
     * @throws Exception
     */
    @Override
    protected void initUserDetailsService() throws Exception {
        for(UserDetailsBuilder userBuilder : userBuilders) {
            getUserDetailsService().createUser(userBuilder.build());
        }
    }

    /**
     * Allows adding a user to the {@link UserDetailsManager} that is being created. This method can be invoked
     * multiple times to add multiple users.
     * 
     * <p> 允许将用户添加到正在创建的UserDetailsManager中。 可以多次调用此方法以添加多个用户。
     *
     * @param username the username for the user being added. Cannot be null.
     * 
     * <p> 要添加的用户的用户名。 不能为null。
     * @return
     */
    @SuppressWarnings("unchecked")
    public final UserDetailsBuilder withUser(String username) {
        UserDetailsBuilder userBuilder = new UserDetailsBuilder((C)this);
        userBuilder.username(username);
        this.userBuilders.add(userBuilder);
        return userBuilder;
    }

    /**
     * Builds the user to be added. At minimum the username, password, and authorities should provided. The remaining
     * attributes have reasonable defaults.
     * 
     * <p> 构建要添加的用户。 至少应提供用户名，密码和授权。 其余属性具有合理的默认值。
     *
     * @param <T> the type of {@link UserDetailsManagerConfigurer} to return for chaining methods.
     * 
     * <p> 要为链接方法返回的UserDetailsManagerConfigurer的类型。
     */
    public class UserDetailsBuilder {
        private String username;
        private String password;
        private List<GrantedAuthority> authorities;
        private boolean accountExpired;
        private boolean accountLocked;
        private boolean credentialsExpired;
        private boolean disabled;
        private final C builder;

        /**
         * Creates a new instance
         * @param builder the builder to return
         */
        private UserDetailsBuilder(C builder) {
            this.builder = builder;
        }

        /**
         * Returns the {@link UserDetailsManagerRegistry} for method chaining (i.e. to add another user)
         * 
         * <p> 返回用于方法链接的UserDetailsManagerRegistry（即添加另一个用户）
         *
         * @return the {@link UserDetailsManagerRegistry} for method chaining (i.e. to add another user)
         * 
         * <p> 用于方法链接的UserDetailsManagerRegistry（即添加另一个用户）
         */
        public C and() {
            return builder;
        }

        /**
         * Populates the username. This attribute is required.
         * 
         * <p> 填充用户名。 此属性是必需的。
         *
         * @param username the username. Cannot be null.
         * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate additional attributes for this
         *         user)
         *         
         * <p> 用于方法链接的UserDetailsBuilder（即为该用户填充其他属性）
         */
        private UserDetailsBuilder username(String username) {
            Assert.notNull(username, "username cannot be null");
            this.username = username;
            return this;
        }

        /**
         * Populates the password. This attribute is required.
         * 
         * <p> 填充密码。 此属性是必需的。
         *
         * @param password the password. Cannot be null.
         * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate additional attributes for this
         *         user)
         *         
         * <p> 用于方法链接的UserDetailsBuilder（即为该用户填充其他属性）
         */
        public UserDetailsBuilder password(String password) {
            Assert.notNull(password, "password cannot be null");
            this.password = password;
            return this;
        }

        /**
         * <p> Populates the roles. This method is a shortcut for calling {@link #authorities(String...)}, but automatically
         * prefixes each entry with "ROLE_". This means the following:
         * 
         * <p> 填充角色。 此方法是调用Authority（String）的快捷方式，但是会自动为每个条目添加“ ROLE_”前缀。 这意味着：
         *
         *<p> 
         * <code>
         *     builder.roles("USER","ADMIN");
         * </code>
         *
         * <p> is equivalent to
         * <p> 相当于
         * <p> 
         * <code>
         *     builder.authorities("ROLE_USER","ROLE_ADMIN");
         * </code>
         *
         * <p>This attribute is required, but can also be populated with {@link #authorities(String...)}.</p>
         * 
         * <p> 此属性是必需的，但也可以用Authority（String）填充。
         *
         * @param roles the roles for this user (i.e. USER, ADMIN, etc). Cannot be null, contain null values or start
         *              with "ROLE_"
         *              
         * <p> 该用户的角色（即USER，ADMIN等）。 不能为null，包含null值或以“ ROLE_”开头
         * 
         * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate additional attributes for this
         *         user)
         *         
         * <p> 用于方法链接的UserDetailsBuilder（即为该用户填充其他属性）
         */
        public UserDetailsBuilder roles(String... roles) {
            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>(roles.length);
            for(String role : roles) {
                Assert.isTrue(!role.startsWith("ROLE_"), role + " cannot start with ROLE_ (it is automatically added)");
                authorities.add(new SimpleGrantedAuthority("ROLE_"+role));
            }
            return authorities(authorities);
        }

        /**
         * Populates the authorities. This attribute is required.
         *
         * @param authorities the authorities for this user. Cannot be null, or contain null
         *                    values
         * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate additional attributes for this
         *         user)
         * @see #roles(String...)
         */
        public UserDetailsBuilder authorities(GrantedAuthority...authorities) {
            return authorities(Arrays.asList(authorities));
        }

        /**
         * Populates the authorities. This attribute is required.
         *
         * @param authorities the authorities for this user. Cannot be null, or contain null
         *                    values
         * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate additional attributes for this
         *         user)
         * @see #roles(String...)
         */
        public UserDetailsBuilder authorities(List<? extends GrantedAuthority> authorities) {
            this.authorities = new ArrayList<GrantedAuthority>(authorities);
            return this;
        }

        /**
         * Populates the authorities. This attribute is required.
         *
         * @param authorities the authorities for this user (i.e. ROLE_USER, ROLE_ADMIN, etc). Cannot be null, or contain null
         *                    values
         * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate additional attributes for this
         *         user)
         * @see #roles(String...)
         */
        public UserDetailsBuilder authorities(String... authorities) {
            return authorities(AuthorityUtils.createAuthorityList(authorities));
        }

        /**
         * Defines if the account is expired or not. Default is false.
         *
         * @param accountExpired true if the account is expired, false otherwise
         * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate additional attributes for this
         *         user)
         */
        public UserDetailsBuilder accountExpired(boolean accountExpired) {
            this.accountExpired = accountExpired;
            return this;
        }

        /**
         * Defines if the account is locked or not. Default is false.
         *
         * @param accountLocked true if the account is locked, false otherwise
         * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate additional attributes for this
         *         user)
         */
        public UserDetailsBuilder accountLocked(boolean accountLocked) {
            this.accountLocked = accountLocked;
            return this;
        }

        /**
         * Defines if the credentials are expired or not. Default is false.
         *
         * @param credentialsExpired true if the credentials are expired, false otherwise
         * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate additional attributes for this
         *         user)
         */
        public UserDetailsBuilder credentialsExpired(boolean credentialsExpired) {
            this.credentialsExpired = credentialsExpired;
            return this;
        }


        /**
         * Defines if the account is disabled or not. Default is false.
         *
         * @param disabled true if the account is disabled, false otherwise
         * @return the {@link UserDetailsBuilder} for method chaining (i.e. to populate additional attributes for this
         *         user)
         */
        public UserDetailsBuilder disabled(boolean disabled) {
            this.disabled = disabled;
            return this;
        }

        private UserDetails build() {
            return new User(username, password, !disabled, !accountExpired,
                    !credentialsExpired, !accountLocked, authorities);
        }
    }
}
