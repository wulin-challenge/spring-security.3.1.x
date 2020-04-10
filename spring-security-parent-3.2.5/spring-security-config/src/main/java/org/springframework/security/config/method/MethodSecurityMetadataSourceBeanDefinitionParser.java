package org.springframework.security.config.method;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.config.Elements;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 *
 * @author Luke Taylor
 * @since 3.1
 */
public class MethodSecurityMetadataSourceBeanDefinitionParser extends AbstractBeanDefinitionParser {
    static final String ATT_METHOD = "method";
    static final String ATT_ACCESS = "access";

    public AbstractBeanDefinition parseInternal(Element elt, ParserContext pc) {
        // Parse the included methods
        List<Element> methods = DomUtils.getChildElementsByTagName(elt, Elements.PROTECT);
        Map<String, List<ConfigAttribute>> mappings = new LinkedHashMap<String, List<ConfigAttribute>>();

        for (Element protectmethodElt : methods) {
            String[] tokens = StringUtils.commaDelimitedListToStringArray(protectmethodElt.getAttribute(ATT_ACCESS));
            String methodName = protectmethodElt.getAttribute(ATT_METHOD);

            mappings.put(methodName, SecurityConfig.createList(tokens));
        }

        RootBeanDefinition metadataSource = new RootBeanDefinition(MapBasedMethodSecurityMetadataSource.class);
        metadataSource.getConstructorArgumentValues().addGenericArgumentValue(mappings);

        return metadataSource;
    }

}
