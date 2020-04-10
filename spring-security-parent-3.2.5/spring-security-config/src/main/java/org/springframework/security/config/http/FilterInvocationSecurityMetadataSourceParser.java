package org.springframework.security.config.http;

import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.config.Elements;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Allows for convenient creation of a {@link FilterInvocationSecurityMetadataSource} bean for use with a FilterSecurityInterceptor.
 *
 * @author Luke Taylor
 */
public class FilterInvocationSecurityMetadataSourceParser implements BeanDefinitionParser {
    private static final String ATT_USE_EXPRESSIONS = "use-expressions";
    private static final String ATT_HTTP_METHOD = "method";
    private static final String ATT_PATTERN = "pattern";
    private static final String ATT_ACCESS = "access";
    private static final Log logger = LogFactory.getLog(FilterInvocationSecurityMetadataSourceParser.class);

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        List<Element> interceptUrls = DomUtils.getChildElementsByTagName(element, "intercept-url");

        // Check for attributes that aren't allowed in this context
        for(Element elt : interceptUrls) {
            if (StringUtils.hasLength(elt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_REQUIRES_CHANNEL))) {
                parserContext.getReaderContext().error("The attribute '" + HttpSecurityBeanDefinitionParser.ATT_REQUIRES_CHANNEL + "' isn't allowed here.", elt);
            }

            if (StringUtils.hasLength(elt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_FILTERS))) {
                parserContext.getReaderContext().error("The attribute '" + HttpSecurityBeanDefinitionParser.ATT_FILTERS + "' isn't allowed here.", elt);
            }
        }

        BeanDefinition mds = createSecurityMetadataSource(interceptUrls, element, parserContext);

        String id = element.getAttribute(AbstractBeanDefinitionParser.ID_ATTRIBUTE);

        if (StringUtils.hasText(id)) {
            parserContext.registerComponent(new BeanComponentDefinition(mds, id));
            parserContext.getRegistry().registerBeanDefinition(id, mds);
        }

        return mds;
    }

    static RootBeanDefinition createSecurityMetadataSource(List<Element> interceptUrls, Element elt, ParserContext pc) {
        MatcherType matcherType = MatcherType.fromElement(elt);
        boolean useExpressions = isUseExpressions(elt);

        ManagedMap<BeanDefinition, BeanDefinition> requestToAttributesMap = parseInterceptUrlsForFilterInvocationRequestMap(
                matcherType, interceptUrls, useExpressions, pc);
        BeanDefinitionBuilder fidsBuilder;

        if (useExpressions) {
            Element expressionHandlerElt = DomUtils.getChildElementByTagName(elt, Elements.EXPRESSION_HANDLER);
            String expressionHandlerRef = expressionHandlerElt == null ? null : expressionHandlerElt.getAttribute("ref");

            if (StringUtils.hasText(expressionHandlerRef)) {
                logger.info("Using bean '" + expressionHandlerRef + "' as web SecurityExpressionHandler implementation");
            } else {
                expressionHandlerRef = registerDefaultExpressionHandler(pc);
            }

            fidsBuilder = BeanDefinitionBuilder.rootBeanDefinition(ExpressionBasedFilterInvocationSecurityMetadataSource.class);
            fidsBuilder.addConstructorArgValue(requestToAttributesMap);
            fidsBuilder.addConstructorArgReference(expressionHandlerRef);
        } else {
            fidsBuilder = BeanDefinitionBuilder.rootBeanDefinition(DefaultFilterInvocationSecurityMetadataSource.class);
            fidsBuilder.addConstructorArgValue(requestToAttributesMap);
        }

        fidsBuilder.getRawBeanDefinition().setSource(pc.extractSource(elt));

        return (RootBeanDefinition) fidsBuilder.getBeanDefinition();
    }

    static String registerDefaultExpressionHandler(ParserContext pc) {
        BeanDefinition expressionHandler = BeanDefinitionBuilder.rootBeanDefinition(DefaultWebSecurityExpressionHandler.class).getBeanDefinition();
        String expressionHandlerRef = pc.getReaderContext().generateBeanName(expressionHandler);
        pc.registerBeanComponent(new BeanComponentDefinition(expressionHandler, expressionHandlerRef));

        return expressionHandlerRef;
    }

    static boolean isUseExpressions(Element elt) {
        return "true".equals(elt.getAttribute(ATT_USE_EXPRESSIONS));
    }

    private static ManagedMap<BeanDefinition, BeanDefinition>
        parseInterceptUrlsForFilterInvocationRequestMap(MatcherType matcherType,
                List<Element> urlElts, boolean useExpressions, ParserContext parserContext) {

        ManagedMap<BeanDefinition, BeanDefinition> filterInvocationDefinitionMap = new ManagedMap<BeanDefinition, BeanDefinition>();

        for (Element urlElt : urlElts) {
            String access = urlElt.getAttribute(ATT_ACCESS);
            if (!StringUtils.hasText(access)) {
                continue;
            }

            String path = urlElt.getAttribute(ATT_PATTERN);

            if(!StringUtils.hasText(path)) {
                parserContext.getReaderContext().error("path attribute cannot be empty or null", urlElt);
            }

            String method = urlElt.getAttribute(ATT_HTTP_METHOD);
            if (!StringUtils.hasText(method)) {
                method = null;
            }

            BeanDefinition matcher = matcherType.createMatcher(path, method);
            BeanDefinitionBuilder attributeBuilder = BeanDefinitionBuilder.rootBeanDefinition(SecurityConfig.class);
            attributeBuilder.addConstructorArgValue(access);

            if (useExpressions) {
                logger.info("Creating access control expression attribute '" + access + "' for " + path);
                // The single expression will be parsed later by the ExpressionFilterInvocationSecurityMetadataSource
                attributeBuilder.setFactoryMethod("createSingleAttributeList");

            } else {
                attributeBuilder.setFactoryMethod("createListFromCommaDelimitedString");
            }

            if (filterInvocationDefinitionMap.containsKey(matcher)) {
                logger.warn("Duplicate URL defined: " + path + ". The original attribute values will be overwritten");
            }

            filterInvocationDefinitionMap.put(matcher, attributeBuilder.getBeanDefinition());
        }

        return filterInvocationDefinitionMap;
    }

}
