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

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A base {@link SecurityBuilder} that ensures the object being built is only
 * built one time.
 * 
 * <p> 确保只构建一次的基础SecurityBuilder只能构建一次。
 *
 * @param <O> the type of Object that is being built
 * 
 * <p> 正在构建的对象的类型
 *
 * @author Rob Winch
 *
 */
public abstract class AbstractSecurityBuilder<O> implements SecurityBuilder<O> {
    private AtomicBoolean building = new AtomicBoolean();

    private O object;

    /* (non-Javadoc)
     * @see org.springframework.security.config.annotation.SecurityBuilder#build()
     */
    public final O build() throws Exception {
        if(building.compareAndSet(false, true)) {
            object = doBuild();
            return object;
        }
        throw new AlreadyBuiltException("This object has already been built");
    }

    /**
     * Gets the object that was built. If it has not been built yet an Exception
     * is thrown.
     *
     * @return the Object that was built
     */
    public final O getObject() {
        if(!building.get()) {
            throw new IllegalStateException("This object has not been built");
        }
        return object;
    }

    /**
     * Subclasses should implement this to perform the build.
     * 
     * <p> 子类应实现此功能以执行构建。
     *
     * @return the object that should be returned by {@link #build()}.
     * 
     * <p> 应该由build（）返回的对象。
     *
     * @throws Exception if an error occurs
     */
    protected abstract O doBuild() throws Exception;
}
