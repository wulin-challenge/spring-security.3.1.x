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

import java.util.LinkedHashMap;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.DelegatingAccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.security.web.session.InvalidSessionAccessDeniedHandler;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Adds <a
 * href="https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)"
 * >CSRF</a> protection for the methods as specified by
 * {@link #requireCsrfProtectionMatcher(RequestMatcher)}.
 * 
 * <p> 为requireCsrfProtectionMatcher（RequestMatcher）指定的方法添加CSRF保护。
 *
 * <h2>Security Filters</h2>
 * 
 * <p> 安全过滤器
 *
 * <p> The following Filters are populated
 * 
 * <p> 下列过滤器已填充
 *
 * <ul>
 * <li>{@link CsrfFilter}</li>
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
 * <ul>
 * <li>
 * {@link ExceptionHandlingConfigurer#accessDeniedHandler(AccessDeniedHandler)}
 * is used to determine how to handle CSRF attempts</li>
 * <li>
 * <li> ExceptionHandlingConfigurer.accessDeniedHandler（AccessDeniedHandler）用于确定如何处理CSRF尝试
 * <li>
 * <li>{@link InvalidSessionStrategy}</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class CsrfConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<CsrfConfigurer<H>,H> {
    private CsrfTokenRepository csrfTokenRepository = new HttpSessionCsrfTokenRepository();
    private RequestMatcher requireCsrfProtectionMatcher;

    /**
     * Creates a new instance
     * @see HttpSecurity#csrf()
     */
    public CsrfConfigurer() {
    }

    /**
     * Specify the {@link CsrfTokenRepository} to use. The default is an {@link HttpSessionCsrfTokenRepository}.
     *
     * @param csrfTokenRepository the {@link CsrfTokenRepository} to use
     * @return the {@link CsrfConfigurer} for further customizations
     */
    public CsrfConfigurer<H> csrfTokenRepository(CsrfTokenRepository csrfTokenRepository) {
        Assert.notNull(csrfTokenRepository, "csrfTokenRepository cannot be null");
        this.csrfTokenRepository = csrfTokenRepository;
        return this;
    }

    /**
     * Specify the {@link RequestMatcher} to use for determining when CSRF
     * should be applied. The default is to ignore GET, HEAD, TRACE, OPTIONS and
     * process all other requests.
     *
     * @param requireCsrfProtectionMatcher
     *            the {@link RequestMatcher} to use
     * @return the {@link CsrfConfigurer} for further customizations
     */
    public CsrfConfigurer<H> requireCsrfProtectionMatcher(RequestMatcher requireCsrfProtectionMatcher) {
        Assert.notNull(csrfTokenRepository, "requireCsrfProtectionMatcher cannot be null");
        this.requireCsrfProtectionMatcher = requireCsrfProtectionMatcher;
        return this;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void configure(H http) throws Exception {
        CsrfFilter filter = new CsrfFilter(csrfTokenRepository);
        if(requireCsrfProtectionMatcher != null) {
            filter.setRequireCsrfProtectionMatcher(requireCsrfProtectionMatcher);
        }
        AccessDeniedHandler accessDeniedHandler = createAccessDeniedHandler(http);
        if(accessDeniedHandler != null) {
            filter.setAccessDeniedHandler(accessDeniedHandler);
        }
        LogoutConfigurer<H> logoutConfigurer = http.getConfigurer(LogoutConfigurer.class);
        if(logoutConfigurer != null) {
            logoutConfigurer.addLogoutHandler(new CsrfLogoutHandler(csrfTokenRepository));
        }
        SessionManagementConfigurer<H> sessionConfigurer = http.getConfigurer(SessionManagementConfigurer.class);
        if(sessionConfigurer != null) {
            sessionConfigurer.addSessionAuthenticationStrategy(new CsrfAuthenticationStrategy(csrfTokenRepository));
        }
        filter = postProcess(filter);
        http.addFilter(filter);
    }

    /**
     * Gets the default {@link AccessDeniedHandler} from the
     * {@link ExceptionHandlingConfigurer#getAccessDeniedHandler()} or create a
     * {@link AccessDeniedHandlerImpl} if not available.
     *
     * @param http the {@link HttpSecurityBuilder}
     * @return the {@link AccessDeniedHandler}
     */
    @SuppressWarnings("unchecked")
    private AccessDeniedHandler getDefaultAccessDeniedHandler(H http) {
        ExceptionHandlingConfigurer<H> exceptionConfig = http.getConfigurer(ExceptionHandlingConfigurer.class);
        AccessDeniedHandler handler = null;
        if(exceptionConfig != null) {
            handler = exceptionConfig.getAccessDeniedHandler();
        }
        if(handler == null) {
            handler = new AccessDeniedHandlerImpl();
        }
        return handler;
    }

    /**
     * Gets the default {@link InvalidSessionStrategy} from the
     * {@link SessionManagementConfigurer#getInvalidSessionStrategy()} or null
     * if not available.
     *
     * @param http
     *            the {@link HttpSecurityBuilder}
     * @return the {@link InvalidSessionStrategy}
     */
    @SuppressWarnings("unchecked")
    private InvalidSessionStrategy getInvalidSessionStrategy(H http) {
        SessionManagementConfigurer<H> sessionManagement = http.getConfigurer(SessionManagementConfigurer.class);
        if(sessionManagement == null) {
            return null;
        }
        return sessionManagement.getInvalidSessionStrategy();
    }

    /**
     * Creates the {@link AccessDeniedHandler} from the result of
     * {@link #getDefaultAccessDeniedHandler(HttpSecurityBuilder)} and
     * {@link #getInvalidSessionStrategy(HttpSecurityBuilder)}. If
     * {@link #getInvalidSessionStrategy(HttpSecurityBuilder)} is non-null, then
     * a {@link DelegatingAccessDeniedHandler} is used in combination with
     * {@link InvalidSessionAccessDeniedHandler} and the
     * {@link #getDefaultAccessDeniedHandler(HttpSecurityBuilder)}. Otherwise,
     * only {@link #getDefaultAccessDeniedHandler(HttpSecurityBuilder)} is used.
     *
     * @param http the {@link HttpSecurityBuilder}
     * @return the {@link AccessDeniedHandler}
     */
    private AccessDeniedHandler createAccessDeniedHandler(H http) {
        InvalidSessionStrategy invalidSessionStrategy = getInvalidSessionStrategy(http);
        AccessDeniedHandler defaultAccessDeniedHandler = getDefaultAccessDeniedHandler(http);
        if(invalidSessionStrategy == null) {
            return defaultAccessDeniedHandler;
        }

        InvalidSessionAccessDeniedHandler invalidSessionDeniedHandler = new InvalidSessionAccessDeniedHandler(invalidSessionStrategy);
        LinkedHashMap<Class<? extends AccessDeniedException>, AccessDeniedHandler> handlers =
                new LinkedHashMap<Class<? extends AccessDeniedException>, AccessDeniedHandler>();
        handlers.put(MissingCsrfTokenException.class, invalidSessionDeniedHandler);
        return new DelegatingAccessDeniedHandler(handlers, defaultAccessDeniedHandler);
    }
}