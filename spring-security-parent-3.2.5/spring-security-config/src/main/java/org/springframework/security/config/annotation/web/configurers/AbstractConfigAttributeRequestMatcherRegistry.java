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

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * A base class for registering {@link RequestMatcher}'s. For example, it might allow for specifying which
 * {@link RequestMatcher} require a certain level of authorization.
 * 
 * <p> 用于注册RequestMatcher的基类。 例如，它可能允许指定哪个RequestMatcher需要一定级别的授权。
 *
 * @author Rob Winch
 * @since 3.2
 *
 * @param <C> The object that is returned or Chained after creating the RequestMatcher
 * 
 * <p> 创建RequestMatcher后返回或链接的对象
 *
 * @see ChannelSecurityConfigurer
 * @see UrlAuthorizationConfigurer
 * @see ExpressionUrlAuthorizationConfigurer
 */
public abstract class AbstractConfigAttributeRequestMatcherRegistry<C> extends AbstractRequestMatcherRegistry<C> {
    private List<UrlMapping> urlMappings = new ArrayList<UrlMapping>();
    private List<RequestMatcher> unmappedMatchers;

    /**
     * Gets the {@link UrlMapping} added by subclasses in {@link #chainRequestMatchers(java.util.List)}. May be empty.
     * 
     * <p> 获取由chainRequestMatchers（java.util.List）中的子类添加的UrlMapping。 可能是空的。
     *
     * @return the {@link UrlMapping} added by subclasses in {@link #chainRequestMatchers(java.util.List)}
     * 
     * <p> 子类在chainRequestMatchers（java.util.List）中添加的UrlMapping
     */
    final List<UrlMapping> getUrlMappings() {
        return urlMappings;
    }

    /**
     * Adds a {@link UrlMapping} added by subclasses in
     * {@link #chainRequestMatchers(java.util.List)} and resets the unmapped
     * {@link RequestMatcher}'s.
     *
     * @param urlMapping
     *            {@link UrlMapping} the mapping to add
     */
    final void addMapping(UrlMapping urlMapping) {
        this.unmappedMatchers = null;
        this.urlMappings.add(urlMapping);
    }

    /**
     * Marks the {@link RequestMatcher}'s as unmapped and then calls {@link #chainRequestMatchersInternal(List)}.
     * 
     * <p> 将RequestMatcher标记为未映射，然后调用chainRequestMatchersInternal（List）。
     *
     * @param requestMatchers the {@link RequestMatcher} instances that were created
     * 
     * <p> 创建的RequestMatcher实例
     * 
     * @return the chained Object for the subclass which allows association of something else to the
     *         {@link RequestMatcher}
     *         
     * <p> 子类的链接对象，允许将其他内容关联到RequestMatcher
     */
    protected final C chainRequestMatchers(List<RequestMatcher> requestMatchers) {
        this.unmappedMatchers = requestMatchers;
        return chainRequestMatchersInternal(requestMatchers);
    }

    /**
     * Subclasses should implement this method for returning the object that is chained to the creation of the
     * {@link RequestMatcher} instances.
     * 
     * <p> 子类应实现此方法，以返回链接到创建RequestMatcher实例的对象。
     *
     * @param requestMatchers the {@link RequestMatcher} instances that were created
     * 
     * <p> 创建的RequestMatcher实例
     * 
     * @return the chained Object for the subclass which allows association of something else to the
     *         {@link RequestMatcher}
     *         
     * <p> 子类的链接对象，允许将其他内容关联到RequestMatcher
     */
     protected abstract C chainRequestMatchersInternal(List<RequestMatcher> requestMatchers);

    /**
     * Adds a {@link UrlMapping} added by subclasses in {@link #chainRequestMatchers(java.util.List)} at a particular
     * index.
     * 
     * <p> 在特定索引处添加由chainRequestMatchers（java.util.List）中的子类添加的UrlMapping。
     *
     * @param index the index to add a {@link UrlMapping}
     * 
     * <p> 添加一个UrlMapping的索引
     * 
     * @param urlMapping {@link UrlMapping} the mapping to add
     * 
     * <p> UrlMapping映射以添加
     */
    final void addMapping(int index, UrlMapping urlMapping) {
        this.urlMappings.add(index, urlMapping);
    }

    /**
     * Creates the mapping of {@link RequestMatcher} to {@link Collection} of {@link ConfigAttribute} instances
     * 
     * <p> 创建RequestMatcher到ConfigAttribute实例集合的映射
     *
     * @return the mapping of {@link RequestMatcher} to {@link Collection} of {@link ConfigAttribute} instances. Cannot
     *         be null.
     *         
     * <p> RequestMatcher到ConfigAttribute实例的Collection的映射。 不能为null。
     */
    final LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> createRequestMap() {
        if(unmappedMatchers != null) {
            throw new IllegalStateException("An incomplete mapping was found for " + unmappedMatchers +". Try completing it with something like requestUrls().<something>.hasRole('USER')");
        }

        LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();
        for (UrlMapping mapping : getUrlMappings()) {
            RequestMatcher matcher = mapping.getRequestMatcher();
            Collection<ConfigAttribute> configAttrs = mapping.getConfigAttrs();
            requestMap.put(matcher,configAttrs);
        }
        return requestMap;
    }

    /**
     * A mapping of {@link RequestMatcher} to {@link Collection} of {@link ConfigAttribute} instances
     * 
     * <p> RequestMatcher到ConfigAttribute实例的集合的映射
     */
    static final class UrlMapping {
        private RequestMatcher requestMatcher;
        private Collection<ConfigAttribute> configAttrs;

        UrlMapping(RequestMatcher requestMatcher,
                Collection<ConfigAttribute> configAttrs) {
            this.requestMatcher = requestMatcher;
            this.configAttrs = configAttrs;
        }

        public RequestMatcher getRequestMatcher() {
            return requestMatcher;
        }

        public Collection<ConfigAttribute> getConfigAttrs() {
            return configAttrs;
        }
    }
}

