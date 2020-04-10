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

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;

/**
 * Adds a Filter that will generate a login page if one is not specified otherwise when using {@link WebSecurityConfigurerAdapter}.
 *
 *<p> 添加一个筛选器，如果未指定登录名，则该筛选器将生成登录页面，否则使用WebSecurityConfigurerAdapter时。
 *
 * <p>
 * By default an {@link org.springframework.security.web.access.channel.InsecureChannelProcessor} and a {@link org.springframework.security.web.access.channel.SecureChannelProcessor} will be registered.
 * </p>
 *
 * <p> 默认情况下，将注册org.springframework.security.web.access.channel.InsecureChannelProcessor和
 * org.springframework.security.web.access.channel.SecureChannelProcessor。
 * 
 * <h2>Security Filters</h2>
 * <p> 安全过滤器
 *
 * <p> The following Filters are conditionally populated
 * 
 * <p> 以下过滤器是有条件填充的
 *
 * <ul>
 *     <li>{@link DefaultLoginPageGeneratingFilter} if the {@link FormLoginConfigurer} did not have a login page specified</li>
 *     <li> DefaultLoginPageGeneratingFilter（如果FormLoginConfigurer没有指定登录页面）
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 * <p> 创建共享对象
 *
 * <p> No shared objects are created.
 *isLogoutRequest
 *
 * <p> 没有创建共享对象。 isLogoutRequest
 *
 * <h2>Shared Objects Used</h2>
 * 
 * <p> 使用的共享对象
 *
 * <p> The following shared objects are used:
 * 
 * <p> 使用以下共享库：
 *
 * <ul>
 *     <li>{@link org.springframework.security.web.PortMapper} is used to create the default {@link org.springframework.security.web.access.channel.ChannelProcessor} instances</li>
 *     <li>
 *     <li> org.springframework.security.web.PortMapper用于创建默认的org.springframework.security.web.access.channel.ChannelProcessor实例。
 *     <li>
 *     <li>{@link FormLoginConfigurer} is used to determine if the {@link DefaultLoginPageConfigurer} should be added and how to configure it.</li>
 *     <li>
 *     <li> FormLoginConfigurer用于确定是否应添加DefaultLoginPageConfigurer以及如何对其进行配置。
 * </ul>
 *
 * @see WebSecurityConfigurerAdapter
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class DefaultLoginPageConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractHttpConfigurer<DefaultLoginPageConfigurer<H>,H> {

    private DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = new DefaultLoginPageGeneratingFilter();

    @Override
    public void init(H http) throws Exception {
        http.setSharedObject(DefaultLoginPageGeneratingFilter.class, loginPageGeneratingFilter);
    }

    @Override
    @SuppressWarnings("unchecked")
    public void configure(H http) throws Exception {
        AuthenticationEntryPoint authenticationEntryPoint = null;
        ExceptionHandlingConfigurer<?> exceptionConf = http.getConfigurer(ExceptionHandlingConfigurer.class);
        if(exceptionConf != null) {
            authenticationEntryPoint = exceptionConf.getAuthenticationEntryPoint();
        }

        if(loginPageGeneratingFilter.isEnabled() && authenticationEntryPoint == null) {
            loginPageGeneratingFilter = postProcess(loginPageGeneratingFilter);
            http.addFilter(loginPageGeneratingFilter);
        }
    }


}