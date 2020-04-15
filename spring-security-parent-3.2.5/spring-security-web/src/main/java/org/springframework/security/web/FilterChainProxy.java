/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;


/**
 * Delegates {@code Filter} requests to a list of Spring-managed filter beans.
 * As of version 2.0, you shouldn't need to explicitly configure a {@code FilterChainProxy} bean in your application
 * context unless you need very fine control over the filter chain contents. Most cases should be adequately covered
 * by the default {@code &lt;security:http /&gt;} namespace configuration options.
 * 
 * <p> 将过滤器请求委托给Spring管理的过滤器bean列表。从2.0版开始，除非您需要对过滤器链内容进行非常精细的控制，
 * 否则您无需在应用程序上下文中显式配置FilterChainProxy bean。默认情况下，<security：http>名称空间配置选项应足以覆盖大多数情况。
 * 
 * <p>
 * The {@code FilterChainProxy} is linked into the servlet container filter chain by adding a standard
 * Spring {@link DelegatingFilterProxy} declaration in the application {@code web.xml} file.
 * 
 * <p> 通过在应用程序web.xml文件中添加标准Spring DelegatingFilterProxy声明，将FilterChainProxy链接到servlet容器过滤器链。
 *
 * <h2>Configuration</h2>
 * <p> 组态
 * 
 * <p>
 * As of version 3.1, {@code FilterChainProxy} is configured using a list of {@link SecurityFilterChain} instances,
 * each of which contains a {@link RequestMatcher} and a list of filters which should be applied to matching requests.
 * Most applications will only contain a single filter chain, and if you are using the namespace, you don't have to
 * set the chains explicitly. If you require finer-grained control, you can make use of the {@code &lt;filter-chain&gt;}
 * namespace element. This defines a URI pattern and the list of filters (as comma-separated bean names) which should be
 * applied to requests which match the pattern. An example configuration might look like this:
 * 
 * <p> 从3.1版开始，FilterChainProxy使用SecurityFilterChain实例列表进行配置，每个实例都包含一个RequestMatcher
 * 和应应用于匹配请求的筛选器列表。大多数应用程序仅包含一个过滤器链，如果您使用的是名称空间，则不必显式设置链。如果需要更细粒度的控制，
 * 则可以使用<filter-chain>命名空间元素。这定义了一个URI模式和过滤器列表（以逗号分隔的bean名称），这些过滤器列表应应用于与该模式匹配的请求。
 * 配置示例如下所示：
 * 
 *
 * <pre>
 &lt;bean id="myfilterChainProxy" class="org.springframework.security.util.FilterChainProxy">
     &lt;constructor-arg>
         &lt;util:list>
             &lt;security:filter-chain pattern="/do/not/filter*" filters="none"/>
             &lt;security:filter-chain pattern="/**" filters="filter1,filter2,filter3"/>
         &lt;/util:list>
     &lt;/constructor-arg>
 &lt;/bean>
 * </pre>
 *
 * The names "filter1", "filter2", "filter3" should be the bean names of {@code Filter} instances defined in the
 * application context. The order of the names defines the order in which the filters will be applied. As shown above,
 * use of the value "none" for the "filters" can be used to exclude a request pattern from the security filter chain
 * entirely. Please consult the security namespace schema file for a full list of available configuration options.
 * 
 * <p> 名称“ filter1”，“ filter2”，“ filter3”应该是在应用程序上下文中定义的Filter实例的bean名称。名称的顺序定义了应用过滤器的顺序。
 * 如上所示，对“过滤器”使用值“无”可用于从安全过滤器链中完全排除请求模式。请查阅安全名称空间架构文件以获取可用配置选项的完整列表。
 *
 * <h2>Request Handling</h2>
 * <p> 请求处理
 * <p>
 * Each possible pattern that the {@code FilterChainProxy} should service must be entered.
 * The first match for a given request will be used to define all of the {@code Filter}s that apply to that
 * request. This means you must put most specific matches at the top of the list, and ensure all {@code Filter}s
 * that should apply for a given matcher are entered against the respective entry.
 * The {@code FilterChainProxy} will not iterate through the remainder of the map entries to locate additional
 * {@code Filter}s.
 * 
 * <p> 必须输入FilterChainProxy应该服务的每种可能的模式。给定请求的第一个匹配项将用于定义适用于该请求的所有过滤器。这意味着您必须将
 * 最特定的匹配项放在列表的顶部，并确保针对相应匹配项应应用的所有过滤器均已在相应条目中输入。 FilterChainProxy将不会遍历地图条目的其余
 * 部分以查找其他过滤器。
 * 
 * <p>
 * {@code FilterChainProxy} respects normal handling of {@code Filter}s that elect not to call {@link
 * javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse,
 * javax.servlet.FilterChain)}, in that the remainder of the original or {@code FilterChainProxy}-declared filter
 * chain will not be called.
 * 
 * <p> FilterChainProxy尊重选择不调用javax.servlet.Filter.doFilter（javax.servlet.ServletRequest，
 * javax.servlet.ServletResponse，javax.servlet.FilterChain）的过滤器的正常处理，因为原始过滤器或FilterChainProxy
 * 声明的过滤器的其余部分链不会被调用。
 *
 * <h3>Request Firewalling</h3>
 * <p> 请求防火墙
 *
 * An {@link HttpFirewall} instance is used to validate incoming requests and create a wrapped request which provides
 * consistent path values for matching against. See {@link DefaultHttpFirewall}, for more information on the type of
 * attacks which the default implementation protects against. A custom implementation can be injected to provide
 * stricter control over the request contents or if an application needs to support certain types of request which
 * are rejected by default.
 * 
 * <p> HttpFirewall实例用于验证传入请求并创建包装的请求，该请求提供一致的路径值以进行匹配。有关默认实现可防御的攻击类型的更多信息，
 * 请参见DefaultHttpFirewall。可以注入自定义实现，以提供对请求内容的更严格控制，或者如果应用程序需要支持默认情况下拒绝的某些类型的请求。
 * 
 * <p>
 * Note that this means that you must use the Spring Security filters in combination with a {@code FilterChainProxy}
 * if you want this protection. Don't define them explicitly in your {@code web.xml} file.
 * 
 * <p> 请注意，这意味着如果需要这种保护，必须将Spring Security过滤器与FilterChainProxy结合使用。不要在web.xml文件中明确定义它们。
 * 
 * <p>
 * {@code FilterChainProxy} will use the firewall instance to obtain both request and response objects which will be
 * fed down the filter chain, so it is also possible to use this functionality to control the functionality of the
 * response. When the request has passed through the security filter chain, the {@code reset} method will be called.
 * With the default implementation this means that the original values of {@code servletPath} and {@code pathInfo} will
 * be returned thereafter, instead of the modified ones used for security pattern matching.
 * 
 * <p> FilterChainProxy将使用防火墙实例来获取请求和响应对象，这些对象将沿着过滤器链向下馈送，因此也可以使用此功能来控制响应的功能。
 * 当请求通过安全过滤器链时，将调用reset方法。使用默认实现，这意味着此后将返回ServletPath和pathInfo的原始值，
 * 而不是用于安全模式匹配的修改后的值。
 * 
 * <p>
 * Since this additional wrapping functionality is performed by the {@code FilterChainProxy}, we don't recommend that
 * you use multiple instances in the same filter chain. It shouldn't be considered purely as a utility for wrapping
 * filter beans in a single {@code Filter} instance.
 * 
 * <p> 由于此附加包装功能是由FilterChainProxy执行的，因此我们不建议您在同一过滤器链中使用多个实例。不应纯粹将其视为在单个
 * Filter实例中包装filter bean的实用程序。
 *
 * <h2>Filter Lifecycle</h2>
 * 
 * <p> 过滤器生命周期
 * 
 * <p>
 * Note the {@code Filter} lifecycle mismatch between the servlet container and IoC
 * container. As described in the {@link DelegatingFilterProxy} Javadocs, we recommend you allow the IoC
 * container to manage the lifecycle instead of the servlet container. {@code FilterChainProxy} does not invoke the
 * standard filter lifecycle methods on any filter beans that you add to the application context.
 * 
 * <p> 注意Servlet容器和IoC容器之间的Filter生命周期不匹配。如DelegatingFilterProxy Javadocs中所述，建议您允许
 * IoC容器而不是Servlet容器来管理生命周期。 FilterChainProxy不会在添加到应用程序上下文中的任何过滤器bean上调用标准过滤器生命周期方法。
 *
 * @author Carlos Sanchez
 * @author Ben Alex
 * @author Luke Taylor
 * @author Rob Winch
 */
public class FilterChainProxy extends GenericFilterBean {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(FilterChainProxy.class);

    //~ Instance fields ================================================================================================

    private final static String FILTER_APPLIED = FilterChainProxy.class.getName().concat(".APPLIED");

    private List<SecurityFilterChain> filterChains;

    private FilterChainValidator filterChainValidator = new NullFilterChainValidator();

    private HttpFirewall firewall = new DefaultHttpFirewall();

    //~ Methods ========================================================================================================

    public FilterChainProxy() {
    }

    public FilterChainProxy(SecurityFilterChain chain) {
        this(Arrays.asList(chain));
    }

    public FilterChainProxy(List<SecurityFilterChain> filterChains) {
        this.filterChains = filterChains;
    }

    @Override
    public void afterPropertiesSet() {
        filterChainValidator.validate(this);
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        boolean clearContext = request.getAttribute(FILTER_APPLIED) == null;
        if(clearContext) {
            try {
                request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
                doFilterInternal(request, response, chain);
            } finally {
                SecurityContextHolder.clearContext();
                request.removeAttribute(FILTER_APPLIED);
            }
        } else {
            doFilterInternal(request, response, chain);
        }
    }

    private void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        FirewalledRequest fwRequest = firewall.getFirewalledRequest((HttpServletRequest) request);
        HttpServletResponse fwResponse = firewall.getFirewalledResponse((HttpServletResponse) response);

        List<Filter> filters = getFilters(fwRequest);

        if (filters == null || filters.size() == 0) {
            if (logger.isDebugEnabled()) {
                logger.debug(UrlUtils.buildRequestUrl(fwRequest) +
                        (filters == null ? " has no matching filters" : " has an empty filter list"));
            }

            fwRequest.reset();

            chain.doFilter(fwRequest, fwResponse);

            return;
        }

        VirtualFilterChain vfc = new VirtualFilterChain(fwRequest, chain, filters);
        vfc.doFilter(fwRequest, fwResponse);
    }

    /**
     * Returns the first filter chain matching the supplied URL.
     *
     * @param request the request to match
     * @return an ordered array of Filters defining the filter chain
     */
    private List<Filter> getFilters(HttpServletRequest request)  {
        for (SecurityFilterChain chain : filterChains) {
            if (chain.matches(request)) {
                return chain.getFilters();
            }
        }

        return null;
    }

    /**
     * Convenience method, mainly for testing.
     *
     * @param url the URL
     * @return matching filter list
     */
    public List<Filter> getFilters(String url) {
        return getFilters(firewall.getFirewalledRequest((new FilterInvocation(url, null).getRequest())));
    }

    /**
     * Sets the mapping of URL patterns to filter chains.
     *
     * The map keys should be the paths and the values should be arrays of {@code Filter} objects.
     * It's VERY important that the type of map used preserves ordering - the order in which the iterator
     * returns the entries must be the same as the order they were added to the map, otherwise you have no way
     * of guaranteeing that the most specific patterns are returned before the more general ones. So make sure
     * the Map used is an instance of {@code LinkedHashMap} or an equivalent, rather than a plain {@code HashMap}, for
     * example.
     *
     * @param filterChainMap the map of path Strings to {@code List&lt;Filter&gt;}s.
     * @deprecated Use the constructor which takes a {@code List&lt;SecurityFilterChain&gt;} instead.
     */
    @Deprecated
    public void setFilterChainMap(Map<RequestMatcher, List<Filter>> filterChainMap) {
        filterChains = new ArrayList<SecurityFilterChain>(filterChainMap.size());

        for (Map.Entry<RequestMatcher,List<Filter>> entry : filterChainMap.entrySet()) {
            filterChains.add(new DefaultSecurityFilterChain(entry.getKey(), entry.getValue()));
        }
    }

    /**
     * Returns a copy of the underlying filter chain map. Modifications to the map contents
     * will not affect the FilterChainProxy state.
     *
     * @return the map of path pattern Strings to filter chain lists (with ordering guaranteed).
     *
     * @deprecated use the list of {@link SecurityFilterChain}s instead
     */
    @Deprecated
    public Map<RequestMatcher, List<Filter>> getFilterChainMap() {
        LinkedHashMap<RequestMatcher, List<Filter>> map =  new LinkedHashMap<RequestMatcher, List<Filter>>();

        for (SecurityFilterChain chain : filterChains) {
            map.put(((DefaultSecurityFilterChain)chain).getRequestMatcher(), chain.getFilters());
        }

        return map;
    }

    /**
     * @return the list of {@code SecurityFilterChain}s which will be matched against and
     *         applied to incoming requests.
     */
    public List<SecurityFilterChain> getFilterChains() {
        return Collections.unmodifiableList(filterChains);
    }

    /**
     * Used (internally) to specify a validation strategy for the filters in each configured chain.
     *
     * @param filterChainValidator the validator instance which will be invoked on during initialization
     * to check the {@code FilterChainProxy} instance.
     */
    public void setFilterChainValidator(FilterChainValidator filterChainValidator) {
        this.filterChainValidator = filterChainValidator;
    }

    /**
     * Sets the "firewall" implementation which will be used to validate and wrap (or potentially reject) the
     * incoming requests. The default implementation should be satisfactory for most requirements.
     *
     * @param firewall
     */
    public void setFirewall(HttpFirewall firewall) {
        this.firewall = firewall;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("FilterChainProxy[");
        sb.append("Filter Chains: ");
        sb.append(filterChains);
        sb.append("]");

        return sb.toString();
    }

    //~ Inner Classes ==================================================================================================

    /**
     * Internal {@code FilterChain} implementation that is used to pass a request through the additional
     * internal list of filters which match the request.
     */
    private static class VirtualFilterChain implements FilterChain {
        private final FilterChain originalChain;
        private final List<Filter> additionalFilters;
        private final FirewalledRequest firewalledRequest;
        private final int size;
        private int currentPosition = 0;

        private VirtualFilterChain(FirewalledRequest firewalledRequest, FilterChain chain, List<Filter> additionalFilters) {
            this.originalChain = chain;
            this.additionalFilters = additionalFilters;
            this.size = additionalFilters.size();
            this.firewalledRequest = firewalledRequest;
        }

        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
            if (currentPosition == size) {
                if (logger.isDebugEnabled()) {
                    logger.debug(UrlUtils.buildRequestUrl(firewalledRequest)
                            + " reached end of additional filter chain; proceeding with original chain");
                }

                // Deactivate path stripping as we exit the security filter chain
                this.firewalledRequest.reset();

                originalChain.doFilter(request, response);
            } else {
                currentPosition++;

                Filter nextFilter = additionalFilters.get(currentPosition - 1);

                if (logger.isDebugEnabled()) {
                    logger.debug(UrlUtils.buildRequestUrl(firewalledRequest) + " at position " + currentPosition + " of "
                        + size + " in additional filter chain; firing Filter: '"
                        + nextFilter.getClass().getSimpleName() + "'");
                }

                nextFilter.doFilter(request, response, this);
            }
        }
    }

    public interface FilterChainValidator {
        void validate(FilterChainProxy filterChainProxy);
    }

    private class NullFilterChainValidator implements FilterChainValidator {
        public void validate(FilterChainProxy filterChainProxy) {
        }
    }

}
