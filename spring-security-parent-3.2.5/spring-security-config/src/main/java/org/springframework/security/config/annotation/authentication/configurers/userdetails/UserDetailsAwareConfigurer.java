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
package org.springframework.security.config.annotation.authentication.configurers.userdetails;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Base class that allows access to the {@link UserDetailsService} for using as a default value with {@link AuthenticationManagerBuilder}.
 * 
 * <p> 允许访问UserDetailsService的基类，以用作AuthenticationManagerBuilder的默认值。
 *
 * @author Rob Winch
 *
 * @param <B> the type of the {@link ProviderManagerBuilder} - ProviderManagerBuilder的类型
 * @param <U> the type of {@link UserDetailsService} - UserDetailsService的类型
 */
public abstract class UserDetailsAwareConfigurer<B extends ProviderManagerBuilder<B>, U extends UserDetailsService> extends SecurityConfigurerAdapter<AuthenticationManager,B> {

    /**
     * Gets the {@link UserDetailsService} or null if it is not available
     * 
     * <p> 获取UserDetailsService；如果不可用，则返回null
     * 
     * @return the {@link UserDetailsService} or null if it is not available
     * 
     * <p> UserDetailsService；如果不可用，则返回null
     */
    public abstract U getUserDetailsService();
}
