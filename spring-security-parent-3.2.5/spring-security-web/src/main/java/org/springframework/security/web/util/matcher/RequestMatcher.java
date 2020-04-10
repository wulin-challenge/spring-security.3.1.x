package org.springframework.security.web.util.matcher;

import javax.servlet.http.HttpServletRequest;

/**
 * Simple strategy to match an <tt>HttpServletRequest</tt>.
 * 
 * <p> 匹配HttpServletRequest的简单策略。
 *
 * @author Luke Taylor
 * @since 3.0.2
 */
public interface RequestMatcher {

    /**
     * Decides whether the rule implemented by the strategy matches the supplied request.
     * 
     * <p> 决定策略实施的规则是否与提供的请求匹配。
     *
     * @param request the request to check for a match
     * 
     * <p> 检查匹配的请求
     * 
     * @return true if the request matches, false otherwise
     * 
     * <p> 如果请求匹配，则返回true，否则返回false
     */
    boolean matches(HttpServletRequest request);

}
