package org.springframework.security.config;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;

/**
 * Test bean post processor which injects a message into a PostProcessedMockUserDetailsService.
 *
 * @author Luke Taylor
 */
public class MockUserServiceBeanPostProcessor implements BeanPostProcessor {

    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if (bean instanceof PostProcessedMockUserDetailsService) {
            ((PostProcessedMockUserDetailsService)bean).setPostProcessorWasHere("Hello from the post processor!");
        }

        return bean;
    }
}
