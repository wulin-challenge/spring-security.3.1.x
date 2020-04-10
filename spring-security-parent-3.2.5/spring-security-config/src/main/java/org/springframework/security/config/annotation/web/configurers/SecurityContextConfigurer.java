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
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * Allows persisting and restoring of the {@link SecurityContext} found on the
 * {@link SecurityContextHolder} for each request by configuring the
 * {@link SecurityContextPersistenceFilter}. All properties have reasonable
 * defaults, so no additional configuration is required other than applying this
 * {@link org.springframework.security.config.annotation.SecurityConfigurer}.
 * 
 * <p> 通过配置SecurityContextPersistenceFilter，允许为每个请求保留和还原在SecurityContextHolder上找到的
 * SecurityContext。 所有属性都有合理的默认值，因此除了应用此
 * org.springframework.security.config.annotation.SecurityConfigurer外，不需要其他配置。
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
 * <li>{@link SecurityContextPersistenceFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 * 
 * <p> 创建共享对象
 *
 * <p> No shared objects are created.
 * 
 * <p> 没有创建共享对象。
 *
 * <h2>Shared Objects Used</h2>
 * 
 * <p> 使用的共享对象
 *
 * <p> The following shared objects are used:
 * 
 * <p> 使用以下共享库
 *
 * <ul>
 * <li>If {@link SessionManagementConfigurer}, is provided and set to always,
 * then the
 * {@link SecurityContextPersistenceFilter#setForceEagerSessionCreation(boolean)}
 * will be set to true.</li>
 * 
 * <p> 如果提供了SessionManagementConfigurer，并将其设置为Always，则
 * SecurityContextPersistenceFilter.setForceEagerSessionCreation（boolean）将设置为true。
 * 
 * <li>{@link SecurityContextRepository} must be set and is used on
 * {@link SecurityContextPersistenceFilter}.</li>
 * 
 * <p> 必须设置SecurityContextRepository，并在SecurityContextPersistenceFilter上使用它。
 * 
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class SecurityContextConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<SecurityContextConfigurer<H>,H> {

    /**
     * Creates a new instance
     * @see HttpSecurity#securityContext()
     */
    public SecurityContextConfigurer() {
    }

    /**
     * Specifies the shared {@link SecurityContextRepository} that is to be used
     * 
     * <p> 指定要使用的共享SecurityContextRepository
     * 
     * @param securityContextRepository the {@link SecurityContextRepository} to use
     * @return the {@link HttpSecurity} for further customizations
     * 
     * <p> HttpSecurity进行进一步的自定义
     * 
     */
	public SecurityContextConfigurer<H> securityContextRepository(SecurityContextRepository securityContextRepository) {
        getBuilder().setSharedObject(SecurityContextRepository.class, securityContextRepository);
        return this;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void configure(H http) throws Exception {

        SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);
        SecurityContextPersistenceFilter securityContextFilter = new SecurityContextPersistenceFilter(
                securityContextRepository);
        SessionManagementConfigurer<?> sessionManagement = http.getConfigurer(SessionManagementConfigurer.class);
        SessionCreationPolicy sessionCreationPolicy = sessionManagement == null ? null
                : sessionManagement.getSessionCreationPolicy();
        if (SessionCreationPolicy.ALWAYS == sessionCreationPolicy) {
            securityContextFilter.setForceEagerSessionCreation(true);
        }
        securityContextFilter = postProcess(securityContextFilter);
        http.addFilter(securityContextFilter);
    }
}