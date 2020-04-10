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

/**
 * Interface for building an Object
 * 
 * <p> 为构建一个对象的接口
 * @author Rob Winch
 * @since 3.2
 *
 * @param <O> The type of the Object being built - 所构建对象的类型
 */
public interface SecurityBuilder<O> {

    /**
     * Builds the object and returns it or null.
     * 
     * <p> 构建对象并返回它或为null。
     *
     * @return the Object to be built or null if the implementation allows it.
     * 
     * <p> 要构建的对象；如果实现允许，则为null。
     * 
     * @throws Exception if an error occurred when building the Object
     * 
     * <p> 如果在构建对象时发生错误
     */
    O build() throws Exception;
}
