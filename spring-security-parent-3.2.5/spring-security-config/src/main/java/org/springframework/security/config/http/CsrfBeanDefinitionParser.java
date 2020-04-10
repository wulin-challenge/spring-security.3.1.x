/*
 * Copyright 2002-2012 the original author or authors.
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
package org.springframework.security.config.http;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.DelegatingAccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.security.web.servlet.support.csrf.CsrfRequestDataValueProcessor;
import org.springframework.security.web.session.InvalidSessionAccessDeniedHandler;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * Parser for the {@code CsrfFilter}.
 *
 * @author Rob Winch
 * @since 3.2
 */
public class CsrfBeanDefinitionParser implements BeanDefinitionParser {

    private static final String REQUEST_DATA_VALUE_PROCESSOR = "requestDataValueProcessor";
    private static final String DISPATCHER_SERVLET_CLASS_NAME = "org.springframework.web.servlet.DispatcherServlet";
    private static final String ATT_MATCHER = "request-matcher-ref";
    private static final String ATT_REPOSITORY = "token-repository-ref";

    private String csrfRepositoryRef;
    private BeanDefinition csrfFilter;

    public BeanDefinition parse(Element element, ParserContext pc) {
        boolean webmvcPresent = ClassUtils.isPresent(DISPATCHER_SERVLET_CLASS_NAME, getClass().getClassLoader());
        if(webmvcPresent) {
            RootBeanDefinition beanDefinition = new RootBeanDefinition(CsrfRequestDataValueProcessor.class);
            BeanComponentDefinition componentDefinition =
                    new BeanComponentDefinition(beanDefinition, REQUEST_DATA_VALUE_PROCESSOR);
            pc.registerBeanComponent(componentDefinition);
        }

        csrfRepositoryRef = element.getAttribute(ATT_REPOSITORY);
        String matcherRef = element.getAttribute(ATT_MATCHER);

        if(!StringUtils.hasText(csrfRepositoryRef)) {
            RootBeanDefinition csrfTokenRepository = new RootBeanDefinition(HttpSessionCsrfTokenRepository.class);
            csrfRepositoryRef = pc.getReaderContext().generateBeanName(csrfTokenRepository);
            pc.registerBeanComponent(new BeanComponentDefinition(csrfTokenRepository, csrfRepositoryRef));
        }

        BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(CsrfFilter.class);
        builder.addConstructorArgReference(csrfRepositoryRef);

        if(StringUtils.hasText(matcherRef)) {
            builder.addPropertyReference("requireCsrfProtectionMatcher", matcherRef);
        }

        csrfFilter = builder.getBeanDefinition();
        return csrfFilter;
    }

    /**
     * Populate the AccessDeniedHandler on the {@link CsrfFilter}
     *
     * @param invalidSessionStrategy the {@link InvalidSessionStrategy} to use
     * @param defaultDeniedHandler the {@link AccessDeniedHandler} to use
     */
    void initAccessDeniedHandler(BeanDefinition invalidSessionStrategy, BeanMetadataElement defaultDeniedHandler) {
        BeanMetadataElement accessDeniedHandler = createAccessDeniedHandler(invalidSessionStrategy, defaultDeniedHandler);
        csrfFilter.getPropertyValues().addPropertyValue("accessDeniedHandler", accessDeniedHandler);
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
     * @param invalidSessionStrategy the {@link InvalidSessionStrategy} to use
     * @param defaultDeniedHandler the {@link AccessDeniedHandler} to use
     *
     * @return the {@link BeanMetadataElement} that is the {@link AccessDeniedHandler} to populate on the {@link CsrfFilter}
     */
    private BeanMetadataElement createAccessDeniedHandler(BeanDefinition invalidSessionStrategy, BeanMetadataElement defaultDeniedHandler) {
        if(invalidSessionStrategy == null) {
            return defaultDeniedHandler;
        }
        ManagedMap<Class<? extends AccessDeniedException>,BeanDefinition> handlers =
                new ManagedMap<Class<? extends AccessDeniedException>, BeanDefinition>();
        BeanDefinitionBuilder invalidSessionHandlerBldr = BeanDefinitionBuilder.rootBeanDefinition(InvalidSessionAccessDeniedHandler.class);
        invalidSessionHandlerBldr.addConstructorArgValue(invalidSessionStrategy);
        handlers.put(MissingCsrfTokenException.class, invalidSessionHandlerBldr.getBeanDefinition());

        BeanDefinitionBuilder deniedBldr = BeanDefinitionBuilder.rootBeanDefinition(DelegatingAccessDeniedHandler.class);
        deniedBldr.addConstructorArgValue(handlers);
        deniedBldr.addConstructorArgValue(defaultDeniedHandler);

        return deniedBldr.getBeanDefinition();
    }

    BeanDefinition getCsrfAuthenticationStrategy() {
        BeanDefinitionBuilder csrfAuthenticationStrategy = BeanDefinitionBuilder.rootBeanDefinition(CsrfAuthenticationStrategy.class);
        csrfAuthenticationStrategy.addConstructorArgReference(csrfRepositoryRef);
        return csrfAuthenticationStrategy.getBeanDefinition();
    }

    BeanDefinition getCsrfLogoutHandler() {
        BeanDefinitionBuilder csrfAuthenticationStrategy = BeanDefinitionBuilder.rootBeanDefinition(CsrfLogoutHandler.class);
        csrfAuthenticationStrategy.addConstructorArgReference(csrfRepositoryRef);
        return csrfAuthenticationStrategy.getBeanDefinition();
    }
}
