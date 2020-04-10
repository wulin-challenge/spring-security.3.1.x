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
package org.springframework.security.config.annotation.authentication;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.SecurityBuilder;

/**
 * Interface for operating on a SecurityBuilder that creates a {@link ProviderManager}
 * 
 * <p> 用于在创建ProviderManager的SecurityBuilder上进行操作的界面
 *
 * @author Rob Winch
 *
 * @param <B> the type of the {@link SecurityBuilder}
 * 
 * <p> SecurityBuilder的类型
 */
public interface ProviderManagerBuilder<B extends ProviderManagerBuilder<B>> extends SecurityBuilder<AuthenticationManager> {

    /**
     * Add authentication based upon the custom {@link AuthenticationProvider}
     * that is passed in. Since the {@link AuthenticationProvider}
     * implementation is unknown, all customizations must be done externally and
     * the {@link ProviderManagerBuilder} is returned immediately.
     * 
     * <p> 根据传入的自定义AuthenticationProvider添加身份验证。由于AuthenticationProvider实现未知，
     * 因此所有自定义操作必须在外部完成，并且ProviderManagerBuilder立即返回。
     *
     * @return a {@link ProviderManagerBuilder} to allow further authentication
     *         to be provided to the {@link ProviderManagerBuilder}
     *         
     * <p> ProviderManagerBuilder，以允许向ProviderManagerBuilder提供进一步的身份验证
     * 
     * @throws Exception
     *             if an error occurs when adding the {@link AuthenticationProvider}
     */
    B authenticationProvider(AuthenticationProvider authenticationProvider);
}
