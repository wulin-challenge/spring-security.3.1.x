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

import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;

import org.springframework.beans.factory.BeanClassLoaderAware;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.ImportAware;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.annotation.Order;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.util.ClassUtils;

/**
 * Uses a {@link WebSecurity} to create the {@link FilterChainProxy} that
 * performs the web based security for Spring Security. It then exports the
 * necessary beans. Customizations can be made to {@link WebSecurity} by
 * extending {@link WebSecurityConfigurerAdapter} and exposing it as a
 * {@link Configuration} or implementing {@link WebSecurityConfigurer} and
 * exposing it as a {@link Configuration}. This configuration is imported when
 * using {@link EnableWebSecurity}.
 * 
 * <p> 使用WebSecurity创建FilterChainProxy来执行Spring Security的基于Web的安全性。
 *  然后，它导出必需的豆。 通过扩展WebSecurityConfigurerAdapter并将其作为配置公开，或者实现WebSecurityConfigurer并将其作为配置公开，
 *  可以对WebSecurity进行自定义。 使用EnableWebSecurity时，将导入此配置。
 *
 * @see EnableWebSecurity
 * @see WebSecurity
 *
 * @author Rob Winch
 * @author Keesun Baik
 * @since 3.2
 */
@Configuration
public class WebSecurityConfiguration implements ImportAware, BeanClassLoaderAware {
    private WebSecurity webSecurity;

    private Boolean debugEnabled;

    private List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers;

    private ClassLoader beanClassLoader;

    @Bean
    @DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
    public SecurityExpressionHandler<FilterInvocation> webSecurityExpressionHandler() {
        return webSecurity.getExpressionHandler();
    }

    /**
     * Creates the Spring Security Filter Chain
     * @return
     * @throws Exception
     */
    @Bean(name=AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
    public Filter springSecurityFilterChain() throws Exception {
        boolean hasConfigurers = webSecurityConfigurers != null && !webSecurityConfigurers.isEmpty();
        if(!hasConfigurers) {
            throw new IllegalStateException("At least one non-null instance of "+ WebSecurityConfigurer.class.getSimpleName()+" must be exposed as a @Bean when using @EnableWebSecurity. Hint try extending "+ WebSecurityConfigurerAdapter.class.getSimpleName());
        }
        return webSecurity.build();
    }

    /**
     * Creates the {@link WebInvocationPrivilegeEvaluator} that is necessary for the JSP tag support.
     * @return the {@link WebInvocationPrivilegeEvaluator}
     * @throws Exception
     */
    @Bean
    @DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
    public WebInvocationPrivilegeEvaluator privilegeEvaluator() throws Exception {
        return webSecurity.getPrivilegeEvaluator();
    }

    /**
     * Sets the {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>} instances used to create the web configuration.
     * 
     * <p> 设置用于创建Web配置的<SecurityConfigurer <FilterChainProxy，WebSecurityBuilder>实例。
     *
     * @param objectPostProcessor the {@link ObjectPostProcessor} used to create a {@link WebSecurity} instance
     * 
     * <p> 用于创建WebSecurity实例的ObjectPostProcessor
     * 
     * @param webSecurityConfigurers the {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>} instances used to create the web configuration
     * 
     * <p> 用于创建Web配置的<SecurityConfigurer <FilterChainProxy，WebSecurityBuilder>实例
     * @throws Exception
     */
    @Autowired(required = false)
    public void setFilterChainProxySecurityConfigurer(ObjectPostProcessor<Object> objectPostProcessor,
            @Value("#{@autowiredWebSecurityConfigurersIgnoreParents.getWebSecurityConfigurers()}") List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers) throws Exception {
        webSecurity = objectPostProcessor.postProcess(new WebSecurity(objectPostProcessor));
        if(debugEnabled != null) {
            webSecurity.debug(debugEnabled); 
        }

        Collections.sort(webSecurityConfigurers, AnnotationAwareOrderComparator.INSTANCE);

        Integer previousOrder = null;
        for(SecurityConfigurer<Filter, WebSecurity> config : webSecurityConfigurers) {
            Integer order = AnnotationAwareOrderComparator.lookupOrder(config);
            if(previousOrder != null && previousOrder.equals(order)) {
                throw new IllegalStateException("@Order on WebSecurityConfigurers must be unique. Order of " + order + " was already used, so it cannot be used on " + config + " too.");
            }
            previousOrder = order;
        }
        for(SecurityConfigurer<Filter, WebSecurity> webSecurityConfigurer : webSecurityConfigurers) {
            webSecurity.apply(webSecurityConfigurer);
        }
        this.webSecurityConfigurers = webSecurityConfigurers;
    }

    @Bean
    public AutowiredWebSecurityConfigurersIgnoreParents autowiredWebSecurityConfigurersIgnoreParents(ConfigurableListableBeanFactory beanFactory) {
        return new AutowiredWebSecurityConfigurersIgnoreParents(beanFactory);
    }

    /**
     * A custom verision of the Spring provided AnnotationAwareOrderComparator
     * that uses {@link AnnotationUtils#findAnnotation(Class, Class)} to look on
     * super class instances for the {@link Order} annotation.
     * 
     * <p> Spring的自定义版本提供了AnnotationAwareOrderComparator，
     * 它使用AnnotationUtils.findAnnotation（Class，Class）在超类实例上查找Order注释。
     *
     * @author Rob Winch
     * @since 3.2
     */
    private static class AnnotationAwareOrderComparator extends OrderComparator {
        private static final AnnotationAwareOrderComparator INSTANCE = new AnnotationAwareOrderComparator();

        @Override
        protected int getOrder(Object obj) {
            return lookupOrder(obj);
        }

        private static int lookupOrder(Object obj) {
            if (obj instanceof Ordered) {
                return ((Ordered) obj).getOrder();
            }
            if (obj != null) {
                Class<?> clazz = (obj instanceof Class ? (Class<?>) obj : obj.getClass());
                Order order = AnnotationUtils.findAnnotation(clazz,Order.class);
                if (order != null) {
                    return order.value();
                }
            }
            return Ordered.LOWEST_PRECEDENCE;
        }
    }

    /* (non-Javadoc)
     * @see org.springframework.context.annotation.ImportAware#setImportMetadata(org.springframework.core.type.AnnotationMetadata)
     */
    public void setImportMetadata(AnnotationMetadata importMetadata) {
        Map<String, Object> enableWebSecurityAttrMap = importMetadata.getAnnotationAttributes(EnableWebSecurity.class.getName());
        AnnotationAttributes enableWebSecurityAttrs = AnnotationAttributes.fromMap(enableWebSecurityAttrMap);
        if(enableWebSecurityAttrs == null) {
            // search parent classes
            Class<?> currentClass = ClassUtils.resolveClassName(importMetadata.getClassName(), beanClassLoader);
            for(Class<?> classToInspect = currentClass ;classToInspect != null; classToInspect = classToInspect.getSuperclass()) {
                EnableWebSecurity enableWebSecurityAnnotation = AnnotationUtils.findAnnotation(classToInspect, EnableWebSecurity.class);
                if(enableWebSecurityAnnotation == null) {
                    continue;
                }
                enableWebSecurityAttrMap = AnnotationUtils
                        .getAnnotationAttributes(enableWebSecurityAnnotation);
                enableWebSecurityAttrs = AnnotationAttributes.fromMap(enableWebSecurityAttrMap);
            }
        }
        debugEnabled = enableWebSecurityAttrs.getBoolean("debug");
        if(webSecurity != null) {
            webSecurity.debug(debugEnabled);
        }
    }

    /* (non-Javadoc)
     * @see org.springframework.beans.factory.BeanClassLoaderAware#setBeanClassLoader(java.lang.ClassLoader)
     */
    public void setBeanClassLoader(ClassLoader classLoader) {
        this.beanClassLoader = classLoader;
    }
}
