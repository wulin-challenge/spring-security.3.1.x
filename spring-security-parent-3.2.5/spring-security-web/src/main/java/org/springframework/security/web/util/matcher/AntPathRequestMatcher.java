/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.web.util.matcher;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Matcher which compares a pre-defined ant-style pattern against the URL
 * ({@code servletPath + pathInfo}) of an {@code HttpServletRequest}.
 * The query string of the URL is ignored and matching is case-insensitive or case-sensitive depending on
 * the arguments passed into the constructor.
 * 
 * <p> 匹配器，它将预定义的蚂蚁样式模式与HttpServletRequest的URL（servletPath + pathInfo）进行比较。 
 * URL的查询字符串将被忽略，并且匹配是区分大小写的还是区分大小写的，具体取决于传递给构造函数的参数。
 * 
 * <p>
 * Using a pattern value of {@code /**} or {@code **} is treated as a universal
 * match, which will match any request. Patterns which end with {@code /**} (and have no other wildcards)
 * are optimized by using a substring match &mdash; a pattern of {@code /aaa/**} will match {@code /aaa},
 * {@code /aaa/} and any sub-directories, such as {@code /aaa/bbb/ccc}.
 * </p>
 * 
 * <p> 使用/ **或**的模式值被视为通用匹配，它将匹配任何请求。 以/ **结尾的模式（没有其他通配符）通过使用子字符串匹配进行
 * 优化-/ aaa / **的模式将匹配/ aaa，/ aaa /和任何子目录，例如/ aaa / bbb / cc。
 * 
 * <p>
 * For all other cases, Spring's {@link AntPathMatcher} is used to perform the match. See the Spring documentation
 * for this class for comprehensive information on the syntax used.
 * </p>
 * 
 * <p> 对于所有其他情况，Spring的AntPathMatcher用于执行匹配。 有关所使用语法的全面信息，请参见此类的Spring文档。
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.1
 *
 * @see org.springframework.util.AntPathMatcher
 */
public final class AntPathRequestMatcher implements RequestMatcher {
    private static final Log logger = LogFactory.getLog(AntPathRequestMatcher.class);
    private static final String MATCH_ALL = "/**";

    private final Matcher matcher;
    private final String pattern;
    private final HttpMethod httpMethod;
    private final boolean caseSensitive;

    /**
     * Creates a matcher with the specific pattern which will match all HTTP
     * methods in a case insensitive manner.
     * 
     * <p> 创建具有特定模式的匹配器，该匹配器将以不区分大小写的方式匹配所有HTTP方法。
     *
     * @param pattern
     *            the ant pattern to use for matching
     */
    public AntPathRequestMatcher(String pattern) {
        this(pattern, null);
    }

    /**
     * Creates a matcher with the supplied pattern and HTTP method in a case
     * insensitive manner.
     * 
     * <p> 以不区分大小写的方式使用提供的模式和HTTP方法创建匹配器。
     *
     * @param pattern
     *            the ant pattern to use for matching
     *            
     * <p> 用于匹配的蚂蚁模式
     * 
     * @param httpMethod
     *            the HTTP method. The {@code matches} method will return false
     *            if the incoming request doesn't have the same method.
     *            
     * <p> HTTP方法。 如果传入的请求没有相同的方法，则matchs方法将返回false。
     */
    public AntPathRequestMatcher(String pattern, String httpMethod) {
        this(pattern,httpMethod,false);
    }

    /**
     * Creates a matcher with the supplied pattern which will match the
     * specified Http method
     * 
     * <p> 使用提供的模式创建匹配器，该匹配器将匹配指定的Http方法
     *
     * @param pattern
     *            the ant pattern to use for matching
     *            
     * <p> 用于匹配的蚂蚁模式
     * 
     * @param httpMethod
     *            the HTTP method. The {@code matches} method will return false
     *            if the incoming request doesn't doesn't have the same method.
     *            
     * <p> HTTP方法。 如果传入的请求没有相同的方法，则matchs方法将返回false。
     * 
     * @param caseSensitive
     *            true if the matcher should consider case, else false
     *            
     * <p> 如果匹配器应考虑大小写，则为true，否则为false
     */
    public AntPathRequestMatcher(String pattern, String httpMethod, boolean caseSensitive) {
        Assert.hasText(pattern, "Pattern cannot be null or empty");
        this.caseSensitive = caseSensitive;

        if (pattern.equals(MATCH_ALL) || pattern.equals("**")) {
            pattern = MATCH_ALL;
            matcher = null;
        } else {
            if(!caseSensitive) {
                pattern = pattern.toLowerCase();
            }

            // If the pattern ends with {@code /**} and has no other wildcards, then optimize to a sub-path match
            // 如果模式以/ **结尾并且没有其他通配符，则优化为子路径匹配
            
            if (pattern.endsWith(MATCH_ALL) && pattern.indexOf('?') == -1 &&
                    pattern.indexOf("*") == pattern.length() - 2) {
                matcher = new SubpathMatcher(pattern.substring(0, pattern.length() - 3));
            } else {
                matcher = new SpringAntMatcher(pattern);
            }
        }

        this.pattern = pattern;
        this.httpMethod = StringUtils.hasText(httpMethod) ? HttpMethod.valueOf(httpMethod) : null;
    }

    /**
     * Returns true if the configured pattern (and HTTP-Method) match those of the supplied request.
     * 
     * <p> 如果配置的模式（和HTTP方法）与提供的请求的模式匹配，则返回true。
     *
     * @param request the request to match against. The ant pattern will be matched against the
     *    {@code servletPath} + {@code pathInfo} of the request.
     *    
     * <p> 匹配的请求。 ant模式将与请求的ServletPath + pathInfo匹配。
     */
    public boolean matches(HttpServletRequest request) {
        if (httpMethod != null && request.getMethod() != null && httpMethod != HttpMethod.valueOf(request.getMethod())) {
            if (logger.isDebugEnabled()) {
                logger.debug("Request '" + request.getMethod() + " " + getRequestPath(request) + "'"
                        + " doesn't match '" + httpMethod  + " " + pattern);
            }

            return false;
        }

        if (pattern.equals(MATCH_ALL)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Request '" + getRequestPath(request) + "' matched by universal pattern '/**'");
            }

            return true;
        }

        String url = getRequestPath(request);

        if (logger.isDebugEnabled()) {
            logger.debug("Checking match of request : '" + url + "'; against '" + pattern + "'");
        }

        return matcher.matches(url);
    }

    private String getRequestPath(HttpServletRequest request) {
        String url = request.getServletPath();

        if (request.getPathInfo() != null) {
            url += request.getPathInfo();
        }

        if(!caseSensitive) {
            url = url.toLowerCase();
        }

        return url;
    }

    public String getPattern() {
        return pattern;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof AntPathRequestMatcher)) {
            return false;
        }

        AntPathRequestMatcher other = (AntPathRequestMatcher) obj;
        return this.pattern.equals(other.pattern) &&
                this.httpMethod == other.httpMethod &&
                this.caseSensitive == other.caseSensitive;
    }

    @Override
    public int hashCode() {
        int code = 31 ^ pattern.hashCode();
        if (httpMethod != null) {
            code ^= httpMethod.hashCode();
        }
        return code;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Ant [pattern='").append(pattern).append("'");

        if (httpMethod != null) {
            sb.append(", ").append(httpMethod);
        }

        sb.append("]");

        return sb.toString();
    }

    private static interface Matcher {
        boolean matches(String path);
    }

    private static class SpringAntMatcher implements Matcher {
        private static final AntPathMatcher antMatcher = new AntPathMatcher();

        private final String pattern;

        private SpringAntMatcher(String pattern) {
            this.pattern = pattern;
        }

        public boolean matches(String path) {
            return antMatcher.match(pattern, path);
        }
    }

    /**
     * Optimized matcher for trailing wildcards
     * 
     * <p> 针对尾随通配符的优化匹配器
     */
    private static class SubpathMatcher implements Matcher {
        private final String subpath;
        private final int length;

        private SubpathMatcher(String subpath) {
            assert !subpath.contains("*");
            this.subpath = subpath;
            this.length = subpath.length();
        }

        public boolean matches(String path) {
            return path.startsWith(subpath) && (path.length() == length || path.charAt(length) == '/');
        }
    }
}
