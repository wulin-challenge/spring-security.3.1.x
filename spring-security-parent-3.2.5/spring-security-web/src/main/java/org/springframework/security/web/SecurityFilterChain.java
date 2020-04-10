package org.springframework.security.web;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * Defines a filter chain which is capable of being matched against an {@code HttpServletRequest}.
 * in order to decide whether it applies to that request.
 * 
 * <p> 定义一个可以与HttpServletRequest匹配的过滤器链。 为了决定它是否适用于该请求。
 * 
 * <p>
 * Used to configure a {@code FilterChainProxy}.
 * 
 * <p> 用于配置FilterChainProxy。
 *
 *
 * @author Luke Taylor
 *
 * @since 3.1
 */
public interface SecurityFilterChain {

    boolean matches(HttpServletRequest request);

    List<Filter> getFilters();
}
