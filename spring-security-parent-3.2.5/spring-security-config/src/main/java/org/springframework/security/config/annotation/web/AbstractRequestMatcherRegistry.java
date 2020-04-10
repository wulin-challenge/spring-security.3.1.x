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
package org.springframework.security.config.annotation.web;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.configurers.AbstractConfigAttributeRequestMatcherRegistry;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * A base class for registering {@link RequestMatcher}'s. For example, it might allow for specifying which
 * {@link RequestMatcher} require a certain level of authorization.
 * 
 * <p> 用于注册RequestMatcher的基类。 例如，它可能允许指定哪个RequestMatcher需要一定级别的授权。
 *
 * @param <C> The object that is returned or Chained after creating the RequestMatcher
 * 
 * <p> 创建RequestMatcher后返回或链接的对象
 *
 * @author Rob Winch
 * @since 3.2
 */
public abstract class AbstractRequestMatcherRegistry<C> {
    private static final RequestMatcher ANY_REQUEST = AnyRequestMatcher.INSTANCE;
    /**
     * Maps any request.
     * 
     * <p> 映射任何请求。
     *
     * @param method the {@link HttpMethod} to use or {@code null} for any {@link HttpMethod}.
     * 
     * <p> 要使用的HttpMethod，对于任何HttpMethod都为null。
     * 
     * @param antPatterns the ant patterns to create {@link org.springframework.security.web.util.matcher.AntPathRequestMatcher}
     *                    from
     *                    
     * <p> 蚂蚁模式从创建org.springframework.security.web.util.matcher.AntPathRequestMatcher
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     * 
     * <p> 创建RequestMatcher之后链接的对象
     */
    public C anyRequest() {
        return requestMatchers(ANY_REQUEST);
    }

    /**
     * Maps a {@link List} of {@link org.springframework.security.web.util.matcher.AntPathRequestMatcher} instances.
     *
     * @param method the {@link HttpMethod} to use or {@code null} for any {@link HttpMethod}.
     * @param antPatterns the ant patterns to create {@link org.springframework.security.web.util.matcher.AntPathRequestMatcher}
     *                    from
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     */
    public C antMatchers(HttpMethod method, String... antPatterns) {
        return chainRequestMatchers(RequestMatchers.antMatchers(method, antPatterns));
    }

    /**
     * Maps a {@link List} of {@link org.springframework.security.web.util.matcher.AntPathRequestMatcher} instances that do
     * not care which {@link HttpMethod} is used.
     * 
     * <p> 映射一个org.springframework.security.web.util.matcher.AntPathRequestMatcher实例的列表，这些实例不关心使用哪个HttpMethod。
     *
     * @param antPatterns the ant patterns to create {@link org.springframework.security.web.util.matcher.AntPathRequestMatcher}
     *                    from
     *                    
     * <p> 蚂蚁模式从创建org.springframework.security.web.util.matcher.AntPathRequestMatcher
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     * 
     * <p> 创建RequestMatcher之后链接的对象
     */
    public C antMatchers(String... antPatterns) {
        return chainRequestMatchers(RequestMatchers.antMatchers(antPatterns));
    }

    /**
     * Maps a {@link List} of {@link org.springframework.security.web.util.matcher.RegexRequestMatcher} instances.
     * 
     * <p> 映射org.springframework.security.web.util.matcher.RegexRequestMatcher实例的列表。
     *
     * @param method the {@link HttpMethod} to use or {@code null} for any {@link HttpMethod}.
     * 
     * <p> 要使用的HttpMethod，对于任何HttpMethod都为null。
     * 
     * @param regexPatterns the regular expressions to create
     *                      {@link org.springframework.security.web.util.matcher.RegexRequestMatcher} from
     *                      
     * <p> 从创建org.springframework.security.web.util.matcher.RegexRequestMatcher的正则表达式
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     */
    public C regexMatchers(HttpMethod method, String... regexPatterns) {
        return chainRequestMatchers(RequestMatchers.regexMatchers(method,
                regexPatterns));
    }

    /**
     * Create a {@link List} of {@link org.springframework.security.web.util.matcher.RegexRequestMatcher} instances that do not
     * specify an {@link HttpMethod}.
     * 
     * <p> 创建一个不指定HttpMethod的org.springframework.security.web.util.matcher.RegexRequestMatcher实例列表。
     *
     * @param regexPatterns the regular expressions to create
     *                      {@link org.springframework.security.web.util.matcher.RegexRequestMatcher} from
     *                      
     * <p> 从创建org.springframework.security.web.util.matcher.RegexRequestMatcher的正则表达式
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     * 
     * <p> 创建RequestMatcher之后链接的对象
     */
    public C regexMatchers(String... regexPatterns) {
        return chainRequestMatchers(RequestMatchers.regexMatchers(regexPatterns));
    }

    /**
     * Associates a list of {@link RequestMatcher} instances with the {@link AbstractConfigAttributeRequestMatcherRegistry}
     * 
     * <p> 将RequestMatcher实例列表与AbstractConfigAttributeRequestMatcherRegistry关联
     *
     * @param requestMatchers the {@link RequestMatcher} instances
     *
     * @return the object that is chained after creating the {@link RequestMatcher}
     * 
     * <p> 创建RequestMatcher之后链接的对象
     */
    public C requestMatchers(RequestMatcher... requestMatchers) {
        return chainRequestMatchers(Arrays.asList(requestMatchers));
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
     * <p> 创建的RequestMatcher实例
     */
    protected abstract C chainRequestMatchers(List<RequestMatcher> requestMatchers);

    /**
     * Utilities for creating {@link RequestMatcher} instances.
     * 
     * <p> 用于创建RequestMatcher实例的实用程序。
     *
     * @author Rob Winch
     * @since 3.2
     */
    private static final class RequestMatchers {

        /**
         * Create a {@link List} of {@link AntPathRequestMatcher} instances.
         * 
         * <p> 创建一个AntPathRequestMatcher实例列表。
         *
         * @param httpMethod the {@link HttpMethod} to use or {@code null} for any {@link HttpMethod}.
         * 
         * <p> 要使用的HttpMethod，对于任何HttpMethod都为null。
         * 
         * @param antPatterns the ant patterns to create {@link AntPathRequestMatcher} from
         * 
         * <p> 蚂蚁模式从中创建{@link AntPathRequestMatcher}
         *
         * @return a {@link List} of {@link AntPathRequestMatcher} instances
         * 
         * <p> AntPathRequestMatcher实例列表
         */
        public static List<RequestMatcher> antMatchers(HttpMethod httpMethod, String...antPatterns) {
            String method = httpMethod == null ? null : httpMethod.toString();
            List<RequestMatcher> matchers = new ArrayList<RequestMatcher>();
            for(String pattern : antPatterns) {
                matchers.add(new AntPathRequestMatcher(pattern, method));
            }
            return matchers;
        }

        /**
         * Create a {@link List} of {@link AntPathRequestMatcher} instances that do not specify an {@link HttpMethod}.
         * 
         * <p> 创建未指定HttpMethod的AntPathRequestMatcher实例列表。
         *
         * @param antPatterns the ant patterns to create {@link AntPathRequestMatcher} from
         * 
         * <p> 蚂蚁模式从中创建AntPathRequestMatcher
         *
         * @return a {@link List} of {@link AntPathRequestMatcher} instances
         * 
         * <p> AntPathRequestMatcher实例列表
         */
        public static List<RequestMatcher> antMatchers(String...antPatterns) {
            return antMatchers(null, antPatterns);
        }

        /**
         * Create a {@link List} of {@link RegexRequestMatcher} instances.
         * 
         * <p> 创建一个RegexRequestMatcher实例列表。
         *
         * @param httpMethod the {@link HttpMethod} to use or {@code null} for any {@link HttpMethod}.
         * 
         * <p> 要使用的HttpMethod，对于任何HttpMethod都为null。
         * 
         * @param regexPatterns the regular expressions to create {@link RegexRequestMatcher} from
         * 
         * <p> 从中创建RegexRequestMatcher的正则表达式
         *
         * @return a {@link List} of {@link RegexRequestMatcher} instances
         * 
         * <p> RegexRequestMatcher实例列表
         */
        public static List<RequestMatcher> regexMatchers(HttpMethod httpMethod, String...regexPatterns) {
            String method = httpMethod == null ? null : httpMethod.toString();
            List<RequestMatcher> matchers = new ArrayList<RequestMatcher>();
            for(String pattern : regexPatterns) {
                matchers.add(new RegexRequestMatcher(pattern, method));
            }
            return matchers;
        }

        /**
         * Create a {@link List} of {@link RegexRequestMatcher} instances that do not specify an {@link HttpMethod}.
         * 
         * <p> 创建未指定HttpMethod的RegexRequestMatcher实例列表。
         *
         *  @param regexPatterns the regular expressions to create {@link RegexRequestMatcher} from
         *  
         *  <p> 从中创建RegexRequestMatcher的正则表达式
         *
         * @return a {@link List} of {@link RegexRequestMatcher} instances
         * 
         * <p> RegexRequestMatcher实例列表
         */
        public static List<RequestMatcher> regexMatchers(String...regexPatterns) {
            return regexMatchers(null, regexPatterns);
        }

        private RequestMatchers() {}
    }
}
