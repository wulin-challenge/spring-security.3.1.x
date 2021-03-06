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
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.util.Assert;
import org.springframework.web.filter.DelegatingFilterProxy;

/**
 * <p>A base {@link SecurityBuilder} that allows {@link SecurityConfigurer} to be
 * applied to it. This makes modifying the {@link SecurityBuilder} a strategy
 * that can be customized and broken up into a number of
 * {@link SecurityConfigurer} objects that have more specific goals than that
 * of the {@link SecurityBuilder}.</p>
 * 
 * <p> 基本SecurityBuilder，允许将SecurityConfigurer应用于它。 这使修改SecurityBuilder成为一种策略，
 * 可以对其进行自定义并将其分解为多个SecurityConfigurer对象，这些对象的目标比SecurityBuilder更为具体。
 *
 * <p>For example, a {@link SecurityBuilder} may build an
 * {@link DelegatingFilterProxy}, but a {@link SecurityConfigurer} might
 * populate the {@link SecurityBuilder} with the filters necessary for session
 * management, form based login, authorization, etc.</p>
 * 
 * <p> 例如，SecurityBuilder可以构建DelegatingFilterProxy，但是SecurityConfigurer可以使用会话管理，
 * 基于表单的登录，授权等所需的过滤器填充SecurityBuilder。
 *
 * @see WebSecurity
 *
 * @author Rob Winch
 *
 * @param <O>
 *            The object that this builder returns - 此构建器返回的对象
 * @param <B>
 *            The type of this builder (that is returned by the base class)
 *            
 * <p> 此构建器的类型（由基类返回）
 */
public abstract class AbstractConfiguredSecurityBuilder<O, B extends SecurityBuilder<O>> extends AbstractSecurityBuilder<O> {
    private final Log logger = LogFactory.getLog(getClass());

    private final LinkedHashMap<Class<? extends SecurityConfigurer<O, B>>, List<SecurityConfigurer<O, B>>> configurers =
            new LinkedHashMap<Class<? extends SecurityConfigurer<O, B>>, List<SecurityConfigurer<O, B>>>();

    private final Map<Class<Object>,Object> sharedObjects = new HashMap<Class<Object>,Object>();

    private final boolean allowConfigurersOfSameType;

    private BuildState buildState = BuildState.UNBUILT;

    private ObjectPostProcessor<Object> objectPostProcessor;

    /***
     * Creates a new instance with the provided {@link ObjectPostProcessor}.
     * This post processor must support Object since there are many types of
     * objects that may be post processed.
     * 
     * <p> 使用提供的ObjectPostProcessor创建一个新实例。 该后处理器必须支持Object，因为可以对许多类型的对象进行后处理。
     *
     * @param objectPostProcessor the {@link ObjectPostProcessor} to use
     * 
     * <p> objectPostProcessor要使用的ObjectPostProcessor
     */
    protected AbstractConfiguredSecurityBuilder(ObjectPostProcessor<Object> objectPostProcessor) {
        this(objectPostProcessor,false);
    }

    /***
     * Creates a new instance with the provided {@link ObjectPostProcessor}.
     * This post processor must support Object since there are many types of
     * objects that may be post processed.
     * 
     * <p> 使用提供的ObjectPostProcessor创建一个新实例。 该后处理器必须支持Object，因为可以对许多类型的对象进行后处理。
     *
     * @param objectPostProcessor the {@link ObjectPostProcessor} to use
     * 
     * <p> objectPostProcessor要使用的ObjectPostProcessor
     * 
     * @param allowConfigurersOfSameType if true, will not override other {@link SecurityConfigurer}'s when performing apply
     * 
     * <p> 如果为true，则执行应用时不会覆盖其他SecurityConfigurer
     */
    protected AbstractConfiguredSecurityBuilder(ObjectPostProcessor<Object> objectPostProcessor, boolean allowConfigurersOfSameType) {
        Assert.notNull(objectPostProcessor, "objectPostProcessor cannot be null");
        this.objectPostProcessor = objectPostProcessor;
        this.allowConfigurersOfSameType = allowConfigurersOfSameType;
    }


    /**
     * Similar to {@link #build()} and {@link #getObject()} but checks the state
     * to determine if {@link #build()} needs to be called first.
     * 
     * <p> 与build（）和getObject（）类似，但会检查状态以确定是否需要首先调用build（）。
     *
     * @return the result of {@link #build()} or {@link #getObject()}. If an
     *         error occurs while building, returns null.
     *         
     * <p> build（）或getObject（）的结果。 如果在构建时发生错误，则返回null。
     */
    public O getOrBuild() {
        if(isUnbuilt()) {
            try {
                return build();
            } catch(Exception e) {
                logger.debug("Failed to perform build. Returning null", e);
                return null;
            }
        } else {
            return getObject();
        }
    }

    /**
     * Applies a {@link SecurityConfigurerAdapter} to this
     * {@link SecurityBuilder} and invokes
     * {@link SecurityConfigurerAdapter#setBuilder(SecurityBuilder)}.
     * 
     * <p> SecurityConfigurer的基类，它允许子类仅实现它们感兴趣的方法。它还提供了一种使用SecurityConfigurer的机制，
     * 并在完成后获得对正在配置的SecurityBuilder的访问权限。
     *
     * @param configurer
     * @return
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public <C extends SecurityConfigurerAdapter<O, B>> C apply(C configurer)
            throws Exception {
        add(configurer);
        configurer.addObjectPostProcessor(objectPostProcessor);
        configurer.setBuilder((B) this);
        return configurer;
    }

    /**
     * Applies a {@link SecurityConfigurer} to this {@link SecurityBuilder}
     * overriding any {@link SecurityConfigurer} of the exact same class. Note
     * that object hierarchies are not considered.
     * 
     * <p> 允许配置SecurityBuilder。 首先，所有SecurityConfigurer都会调用其init（SecurityBuilder）方法。 
     * 调用所有init（SecurityBuilder）方法之后，将调用每个configure（SecurityBuilder）方法。
     *
     * @param configurer
     * @return
     * @throws Exception
     */
    public <C extends SecurityConfigurer<O, B>> C apply(C configurer)
            throws Exception {
        add(configurer);
        return configurer;
    }

    /**
     * Sets an object that is shared by multiple {@link SecurityConfigurer}.
     * 
     * <p> 设置由多个SecurityConfigurer共享的对象。
     *
     * @param sharedType the Class to key the shared object by.
     * 
     * <p> 用来作为共享对象密钥的Class。
     * 
     * @param object the Object to store
     * 
     * <p> 要存储的对象
     */
    @SuppressWarnings("unchecked")
    public <C> void setSharedObject(Class<C> sharedType, C object) {
        this.sharedObjects.put((Class<Object>) sharedType, object);
    }

    /**
     * Gets a shared Object. Note that object heirarchies are not considered.
     * 
     * <p> 获取共享对象。 请注意，不考虑对象层次结构。
     *
     * @param sharedType the type of the shared Object
     * 
     * <p> 共享对象的类型
     * 
     * @return the shared Object or null if it is not found
     * 
     * <p> 共享对象；如果找不到，则为null
     */
    @SuppressWarnings("unchecked")
    public <C> C getSharedObject(Class<C> sharedType) {
        return (C) this.sharedObjects.get(sharedType);
    }

    /**
     * Gets the shared objects
     * 
     * <p> 获取共享对象
     * @return
     */
    public Map<Class<Object>,Object> getSharedObjects() {
        return Collections.unmodifiableMap(this.sharedObjects);
    }

    /**
     * Adds {@link SecurityConfigurer} ensuring that it is allowed and
     * invoking {@link SecurityConfigurer#init(SecurityBuilder)} immediately
     * if necessary.
     * 
     * <p> 添加SecurityConfigurer以确保它被允许，并在必要时立即调用SecurityConfigurer.init（SecurityBuilder）。
     *
     * @param configurer the {@link SecurityConfigurer} to add
     * @throws Exception if an error occurs
     */
    @SuppressWarnings("unchecked")
    private <C extends SecurityConfigurer<O, B>> void add(C configurer) throws Exception {
        Assert.notNull(configurer, "configurer cannot be null");

        Class<? extends SecurityConfigurer<O, B>> clazz = (Class<? extends SecurityConfigurer<O, B>>) configurer
                .getClass();
        synchronized(configurers) {
            if(buildState.isConfigured()) {
                throw new IllegalStateException("Cannot apply "+configurer+" to already built object");
            }
            List<SecurityConfigurer<O, B>> configs = allowConfigurersOfSameType ? this.configurers.get(clazz) : null;
            if(configs == null) {
                configs = new ArrayList<SecurityConfigurer<O,B>>(1);
            }
            configs.add(configurer);
            this.configurers.put(clazz, configs);
            if(buildState.isInitializing()) {
                configurer.init((B)this);
            }
        }
    }

    /**
     * Gets all the {@link SecurityConfigurer} instances by its class name or an
     * empty List if not found. Note that object hierarchies are not considered.
     * 
     * <p> 通过其类名称或空列表（如果找不到）获取所有SecurityConfigurer实例。 请注意，不考虑对象层次结构。
     *
     * @param clazz the {@link SecurityConfigurer} class to look for
     * 
     * <p> 要查找的SecurityConfigurer类
     * @return
     */
    @SuppressWarnings("unchecked")
    public <C extends SecurityConfigurer<O, B>> List<C> getConfigurers(
            Class<C> clazz) {
        List<C> configs = (List<C>) this.configurers.get(clazz);
        if(configs == null) {
            return new ArrayList<C>();
        }
        return new ArrayList<C>(configs);
    }

    /**
     * Removes all the {@link SecurityConfigurer} instances by its class name or an
     * empty List if not found. Note that object hierarchies are not considered.
     * 
     * <p> 通过其类名称或空列表（如果找不到）删除所有SecurityConfigurer实例。 请注意，不考虑对象层次结构。
     *
     * @param clazz the {@link SecurityConfigurer} class to look for
     * 
     * <p> 要查找的SecurityConfigurer类
     * 
     * @return
     */
    @SuppressWarnings("unchecked")
    public <C extends SecurityConfigurer<O, B>> List<C> removeConfigurers(
            Class<C> clazz) {
        List<C> configs = (List<C>) this.configurers.remove(clazz);
        if(configs == null) {
            return new ArrayList<C>();
        }
        return new ArrayList<C>(configs);
    }

    /**
     * Gets the {@link SecurityConfigurer} by its class name or
     * <code>null</code> if not found. Note that object hierarchies are not
     * considered.
     *
     * <p> 通过其类名称获取SecurityConfigurer；如果未找到，则返回null。 请注意，不考虑对象层次结构。
     * 
     * @param clazz
     * @return
     */
    @SuppressWarnings("unchecked")
    public <C extends SecurityConfigurer<O, B>> C getConfigurer(
            Class<C> clazz) {
        List<SecurityConfigurer<O,B>> configs = this.configurers.get(clazz);
        if(configs == null) {
            return null;
        }
        if(configs.size() != 1) {
            throw new IllegalStateException("Only one configurer expected for type " + clazz + ", but got " + configs);
        }
        return (C) configs.get(0);
    }

    /**
     * Removes and returns the {@link SecurityConfigurer} by its class name or
     * <code>null</code> if not found. Note that object hierarchies are not
     * considered.
     * 
     * <p> 移除并返回SecurityConfigurer的类名；如果找不到，则返回null。 请注意，不考虑对象层次结构。
     *
     * @param clazz
     * @return
     */
    @SuppressWarnings("unchecked")
    public <C extends SecurityConfigurer<O,B>> C removeConfigurer(Class<C> clazz) {
        List<SecurityConfigurer<O,B>> configs = this.configurers.remove(clazz);
        if(configs == null) {
            return null;
        }
        if(configs.size() != 1) {
            throw new IllegalStateException("Only one configurer expected for type " + clazz + ", but got " + configs);
        }
        return (C) configs.get(0);
    }

    /**
     * Specifies the {@link ObjectPostProcessor} to use.
     * 
     * <p> 指定要使用的ObjectPostProcessor。
     * 
     * @param objectPostProcessor the {@link ObjectPostProcessor} to use. Cannot be null
     * 
     * <p> 要使用的ObjectPostProcessor。 不能为空
     * 
     * @return the {@link SecurityBuilder} for further customizations
     * 
     * <p> SecurityBuilder进行进一步的自定义
     */
    @SuppressWarnings("unchecked")
    public O objectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
        Assert.notNull(objectPostProcessor,"objectPostProcessor cannot be null");
        this.objectPostProcessor = objectPostProcessor;
        return (O) this;
    }

    /**
     * Performs post processing of an object. The default is to delegate to the
     * {@link ObjectPostProcessor}.
     * 
     * <p> 执行对象的后处理。 默认值为委托给ObjectPostProcessor。
     *
     * @param object the Object to post process - 过帐对象
     * @return the possibly modified Object to use
     * 
     * <p> 可能使用的已修改对象
     */
    protected <P> P postProcess(P object) {
        return (P) this.objectPostProcessor.postProcess(object);
    }

    /**
     * Executes the build using the {@link SecurityConfigurer}'s that have been applied using the following steps:
     * 
     * <p> 使用通过以下步骤应用的SecurityConfigurer执行构建：
     *
     * <ul>
     * <li>Invokes {@link #beforeInit()} for any subclass to hook into</li>
     * <li>
     * <li> 调用beforeInit（）以使任何子类都可以插入
     * <li>
     * <li>Invokes {@link SecurityConfigurer#init(SecurityBuilder)} for any {@link SecurityConfigurer} that was applied to this builder.</li>
     * <li>
     * <li> 为应用于此构建器的任何SecurityConfigurer调用SecurityConfigurer.init（SecurityBuilder）。
     * <li>
     * <li>Invokes {@link #beforeConfigure()} for any subclass to hook into</li>
     * <li>
     * <li> 调用beforeConfigure（）以将任何子类挂接到
     * <li>
     * <li>Invokes {@link #performBuild()} which actually builds the Object</li>
     * <li>
     * <li> 调用performBuild（）实际构建对象
     * </ul>
     */
    @Override
    protected final O doBuild() throws Exception {
        synchronized(configurers) {
            buildState = BuildState.INITIALIZING; //构建状态,表示是初始化阶段

            beforeInit(); //初始化前用户可以通过继承的方式实现一些自定义的逻辑
            init(); //步骤一: 初始化

            buildState = BuildState.CONFIGURING; //构建状态,表示是配置阶段

            beforeConfigure(); // 在配置之前,用户可以通过继承的方式实现一些自定义逻辑
            configure(); // 步骤二: 执行配置

            buildState = BuildState.BUILDING; //构建状态,表示为构建阶段

            O result = performBuild(); //步骤三: 执行构建

            buildState = BuildState.BUILT;// 构建状态,表示构建完成

            return result;
        }
    }

    /**
     * Invoked prior to invoking each
     * {@link SecurityConfigurer#init(SecurityBuilder)} method. Subclasses may
     * override this method to hook into the lifecycle without using a
     * {@link SecurityConfigurer}.
     * 
     * <p> 在调用每个SecurityConfigurer.init（SecurityBuilder）方法之前调用。 子类可以重写此方法以挂接到生命周期，而不使用SecurityConfigurer。
     */
    protected void beforeInit() throws Exception {
    }

    /**
     * Invoked prior to invoking each
     * {@link SecurityConfigurer#configure(SecurityBuilder)} method.
     * Subclasses may override this method to hook into the lifecycle without
     * using a {@link SecurityConfigurer}.
     * 
     * <p> 在调用每个SecurityConfigurer.configure（SecurityBuilder）方法之前调用。 子类可以重写此方法以挂接到生命周期，而不使用SecurityConfigurer。
     */
    protected void beforeConfigure() throws Exception {
    }

    /**
     * Subclasses must implement this method to build the object that is being returned.
     * 
     * <p> 子类必须实现此方法才能构建要返回的对象。
     *
     * @return
     */
    protected abstract O performBuild() throws Exception;

    @SuppressWarnings("unchecked")
    private void init() throws Exception {
        Collection<SecurityConfigurer<O,B>> configurers = getConfigurers();

        for(SecurityConfigurer<O,B> configurer : configurers ) {
            configurer.init((B) this);
        }
    }

    @SuppressWarnings("unchecked")
    private void configure() throws Exception {
        Collection<SecurityConfigurer<O,B>> configurers = getConfigurers();

        for(SecurityConfigurer<O,B> configurer : configurers ) {
            configurer.configure((B) this);
        }
    }

    private Collection<SecurityConfigurer<O, B>> getConfigurers() {
        List<SecurityConfigurer<O,B>> result = new ArrayList<SecurityConfigurer<O,B>>();
        for(List<SecurityConfigurer<O,B>> configs : this.configurers.values()) {
            result.addAll(configs);
        }
        return result;
    }

    /**
     * Determines if the object is unbuilt.
     * 
     * <p> 确定对象是否未构建。
     * 
     * @return true, if unbuilt else false
     * 
     * <p> 是，如果未构建，则为false
     */
    private boolean isUnbuilt() {
        synchronized(configurers) {
            return buildState == BuildState.UNBUILT;
        }
    }

    /**
     * The build state for the application
     * 
     * <p> 应用程序的构建状态
     *
     * @author Rob Winch
     * @since 3.2
     */
    private static enum BuildState {
        /**
         * This is the state before the {@link Builder#build()} is invoked
         * 
         * <p> 这是调用Builder.build（）之前的状态
         */
        UNBUILT(0),

        /**
         * The state from when {@link Builder#build()} is first invoked until
         * all the {@link SecurityConfigurer#init(SecurityBuilder)} methods
         * have been invoked.
         * 
         * <p> 从第一次调用Builder.build（）到所有SecurityConfigurer.init（SecurityBuilder）方法被调用之间的状态。
         */
        INITIALIZING(1),

        /**
         * The state from after all
         * {@link SecurityConfigurer#init(SecurityBuilder)} have been invoked
         * until after all the
         * {@link SecurityConfigurer#configure(SecurityBuilder)} methods have
         * been invoked.
         * 
         * <p> 从所有SecurityConfigurer.init（SecurityBuilder）被调用之后到所有
         * SecurityConfigurer.configure（SecurityBuilder）方法被调用之后的状态。
         */
        CONFIGURING(2),

        /**
         * From the point after all the
         * {@link SecurityConfigurer#configure(SecurityBuilder)} have
         * completed to just after
         * {@link AbstractConfiguredSecurityBuilder#performBuild()}.
         * 
         * <p> 从所有SecurityConfigurer.configure（SecurityBuilder）完成之后到
         * AbstractConfiguredSecurityBuilder.performBuild（）之后。
         */
        BUILDING(3),

        /**
         * After the object has been completely built.
         * 
         * <p> 在对象完全构建之后。
         */
        BUILT(4);

        private final int order;

        BuildState(int order) {
            this.order = order;
        }

        public boolean isInitializing() {
            return INITIALIZING.order == order;
        }

        /**
         * Determines if the state is CONFIGURING or later
         * 
         * 确定状态是CONFIGURING还是更高版本
         * @return
         */
        public boolean isConfigured() {
            return order >= CONFIGURING.order;
        }
    }
}