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
package org.springframework.security.config.annotation;

import java.util.ArrayList;
import java.util.List;

import org.springframework.core.GenericTypeResolver;

/**
 * A base class for {@link SecurityConfigurer} that allows subclasses to only
 * implement the methods they are interested in. It also provides a mechanism
 * for using the {@link SecurityConfigurer} and when done gaining access to the
 * {@link SecurityBuilder} that is being configured.
 * 
 * <p> SecurityConfigurer的基类，它允许子类仅实现它们感兴趣的方法。它还提供了一种使用SecurityConfigurer的机制，
 * 并在完成后获得对正在配置的SecurityBuilder的访问权限。
 *
 * @author Rob Winch
 *
 * @param <O>
 *            The Object being built by B
 *            
 * <p> B正在建立的物件
 * 
 * @param <B>
 *            The Builder that is building O and is configured by {@link SecurityConfigurerAdapter}
 *            
 * <p> 正在构建O并由SecurityConfigurerAdapter配置的生成器
 */
public abstract class SecurityConfigurerAdapter<O,B extends SecurityBuilder<O>> implements SecurityConfigurer<O,B> {
    private B securityBuilder;

    private CompositeObjectPostProcessor objectPostProcessor = new CompositeObjectPostProcessor();

    public void init(B builder) throws Exception {}

    public void configure(B builder) throws Exception {}

    /**
     * Return the {@link SecurityBuilder} when done using the
     * {@link SecurityConfigurer}. This is useful for method chaining.
     *
     * <p> 使用SecurityConfigurer完成后，返回SecurityBuilder。 这对于方法链接很有用。
     * 
     * @return
     */
    public B and() {
        return getBuilder();
    }

    /**
     * Gets the {@link SecurityBuilder}. Cannot be null.
     * 
     * <p> 获取SecurityBuilder。 不能为null。
     * 
     *
     * @return the {@link SecurityBuilder}
     * @throw {@link IllegalStateException} if {@link SecurityBuilder} is null
     */
    protected final B getBuilder() {
        if(securityBuilder == null) {
            throw new IllegalStateException("securityBuilder cannot be null");
        }
        return securityBuilder;
    }

    /**
     * Performs post processing of an object. The default is to delegate to the
     * {@link ObjectPostProcessor}.
     * 
     * <p> 执行对象的后处理。 默认值为委托给ObjectPostProcessor。
     *
     * @param object the Object to post process - 要后处理的对象
     * @return the possibly modified Object to use - 可能使用的已修改对象
     */
    @SuppressWarnings("unchecked")
    protected <T> T postProcess(T object) {
        return (T) this.objectPostProcessor.postProcess(object);
    }

    /**
     * Adds an {@link ObjectPostProcessor} to be used for this
     * {@link SecurityConfigurerAdapter}. The default implementation does
     * nothing to the object.
     * 
     * <p> 添加用于此SecurityConfigurerAdapter的ObjectPostProcessor。 默认实现对对象不执行任何操作。
     *
     * @param objectPostProcessor the {@link ObjectPostProcessor} to use
     * 
     * <p> 要使用的ObjectPostProcessor
     */
    public void addObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
        this.objectPostProcessor.addObjectPostProcessor(objectPostProcessor);
    }

    /**
     * Sets the {@link SecurityBuilder} to be used. This is automatically set
     * when using
     * {@link AbstractConfiguredSecurityBuilder#apply(SecurityConfigurerAdapter)}
     * 
     * <p> 设置要使用的SecurityBuilder。 使用AbstractConfiguredSecurityBuilder.apply（SecurityConfigurerAdapter）时会自动设置
     *
     * @param builder the {@link SecurityBuilder} to set
     * 
     * <p> 要设置的SecurityBuilder
     */
    public void setBuilder(B builder) {
        this.securityBuilder = builder;
    }

    /**
     * An {@link ObjectPostProcessor} that delegates work to numerous
     * {@link ObjectPostProcessor} implementations.
     * 
     * <p> 一个将工作委托给许多ObjectPostProcessor实现的ObjectPostProcessor。
     *
     * @author Rob Winch
     */
    private static final class CompositeObjectPostProcessor implements ObjectPostProcessor<Object> {
        private List<ObjectPostProcessor<? extends Object>> postProcessors = new ArrayList<ObjectPostProcessor<?>>();

        @SuppressWarnings({ "rawtypes", "unchecked" })
        public Object postProcess(Object object) {
            for(ObjectPostProcessor opp : postProcessors) {
                Class<?> oppClass = opp.getClass();
                Class<?> oppType = GenericTypeResolver.resolveTypeArgument(oppClass,ObjectPostProcessor.class);
                if(oppType == null || oppType.isAssignableFrom(object.getClass())) {
                    object = opp.postProcess(object);
                }
            }
            return object;
        }

        /**
         * Adds an {@link ObjectPostProcessor} to use
         * 
         * <p> 添加一个要使用的ObjectPostProcessor
         * 
         * @param objectPostProcessor the {@link ObjectPostProcessor} to add
         * @return true if the {@link ObjectPostProcessor} was added, else false
         */
        private boolean addObjectPostProcessor(ObjectPostProcessor<?extends Object> objectPostProcessor) {
            return this.postProcessors.add(objectPostProcessor);
        }
    }
}
