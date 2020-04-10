package org.springframework.security.config.http;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanDefinitionHolder;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.BeanDefinitionDecorator;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.Elements;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Sets the filter chain Map for a FilterChainProxy bean declaration.
 *
 * @author Luke Taylor
 */
public class FilterChainMapBeanDefinitionDecorator implements BeanDefinitionDecorator {

    @SuppressWarnings("unchecked")
    public BeanDefinitionHolder decorate(Node node, BeanDefinitionHolder holder, ParserContext parserContext) {
        BeanDefinition filterChainProxy = holder.getBeanDefinition();

        Map filterChainMap = new LinkedHashMap();
        Element elt = (Element)node;

        MatcherType matcherType = MatcherType.fromElement(elt);

        List<Element> filterChainElts = DomUtils.getChildElementsByTagName(elt, Elements.FILTER_CHAIN);

        for (Element chain : filterChainElts) {
            String path = chain.getAttribute(HttpSecurityBeanDefinitionParser.ATT_PATH_PATTERN);
            String filters = chain.getAttribute(HttpSecurityBeanDefinitionParser.ATT_FILTERS);

            if(!StringUtils.hasText(path)) {
                parserContext.getReaderContext().error("The attribute '" + HttpSecurityBeanDefinitionParser.ATT_PATH_PATTERN +
                    "' must not be empty", elt);
            }

            if(!StringUtils.hasText(filters)) {
                parserContext.getReaderContext().error("The attribute '" + HttpSecurityBeanDefinitionParser.ATT_FILTERS +
                    "'must not be empty", elt);
            }

            BeanDefinition matcher = matcherType.createMatcher(path, null);

            if (filters.equals(HttpSecurityBeanDefinitionParser.OPT_FILTERS_NONE)) {
                filterChainMap.put(matcher, Collections.EMPTY_LIST);
            } else {
                String[] filterBeanNames = StringUtils.tokenizeToStringArray(filters, ",");
                ManagedList filterChain = new ManagedList(filterBeanNames.length);

                for (String name : filterBeanNames) {
                    filterChain.add(new RuntimeBeanReference(name));
                }

                filterChainMap.put(matcher, filterChain);
            }
        }

        ManagedMap map = new ManagedMap(filterChainMap.size());
        map.putAll(filterChainMap);

        filterChainProxy.getPropertyValues().addPropertyValue("filterChainMap", map);

        return holder;
    }
}
