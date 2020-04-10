package org.springframework.security.authentication;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureCredentialsExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.authentication.event.AuthenticationFailureExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProviderNotFoundEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProxyUntrustedEvent;
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

/**
 * The default strategy for publishing authentication events.
 * 
 * <p> 发布身份验证事件的默认策略。
 * 
 * <p>
 * Maps well-known <tt>AuthenticationException</tt> types to events and publishes them via the
 * application context. If configured as a bean, it will pick up the <tt>ApplicationEventPublisher</tt> automatically.
 * Otherwise, the constructor which takes the publisher as an argument should be used.
 * 
 * <p> 将众所周知的AuthenticationException类型映射到事件，并通过应用程序上下文发布它们。 如果配置为Bean，
 * 它将自动拾取ApplicationEventPublisher。 否则，应使用以发布者为参数的构造函数。
 * 
 * <p>
 * The exception-mapping system can be fine-tuned by setting the <tt>additionalExceptionMappings</tt> as a
 * <code>java.util.Properties</code> object. In the properties object, each of the keys represent the fully qualified
 * classname of the exception, and each of the values represent the name of an event class which subclasses
 * {@link org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent}
 * and provides its constructor. The <tt>additionalExceptionMappings</tt> will be merged with the default ones.
 * 
 * <p> 通过将AdditionalExceptionMappings设置为java.util.Properties对象，可以对异常映射系统进行微调。 
 * 在properties对象中，每个键代表异常的完全限定的类名，每个值代表事件类的名称，该事件类将
 * org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent子类化并提供其构造函数。 
 * AdditionalExceptionMappings将与默认的合并。
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class DefaultAuthenticationEventPublisher implements AuthenticationEventPublisher,
        ApplicationEventPublisherAware {
    private final Log logger = LogFactory.getLog(getClass());

    private ApplicationEventPublisher applicationEventPublisher;
    private final HashMap<String,Constructor<? extends AbstractAuthenticationEvent>> exceptionMappings
            = new HashMap<String,Constructor<? extends AbstractAuthenticationEvent>>();

    public DefaultAuthenticationEventPublisher() {
        this(null);
    }

    public DefaultAuthenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;

        addMapping(BadCredentialsException.class.getName(), AuthenticationFailureBadCredentialsEvent.class);
        addMapping(UsernameNotFoundException.class.getName(), AuthenticationFailureBadCredentialsEvent.class);
        addMapping(AccountExpiredException.class.getName(), AuthenticationFailureExpiredEvent.class);
        addMapping(ProviderNotFoundException.class.getName(), AuthenticationFailureProviderNotFoundEvent.class);
        addMapping(DisabledException.class.getName(), AuthenticationFailureDisabledEvent.class);
        addMapping(LockedException.class.getName(), AuthenticationFailureLockedEvent.class);
        addMapping(AuthenticationServiceException.class.getName(), AuthenticationFailureServiceExceptionEvent.class);
        addMapping(CredentialsExpiredException.class.getName(), AuthenticationFailureCredentialsExpiredEvent.class);
        addMapping("org.springframework.security.authentication.cas.ProxyUntrustedException",
                AuthenticationFailureProxyUntrustedEvent.class);
    }

    public void publishAuthenticationSuccess(Authentication authentication) {
        if (applicationEventPublisher != null) {
            applicationEventPublisher.publishEvent(new AuthenticationSuccessEvent(authentication));
        }
    }

    public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
        Constructor<? extends AbstractAuthenticationEvent> constructor = exceptionMappings.get(exception.getClass().getName());
        AbstractAuthenticationEvent event = null;

        if (constructor != null) {
            try {
                event = constructor.newInstance(authentication, exception);
            } catch (IllegalAccessException ignored) {}
            catch (InstantiationException ignored) {}
            catch (InvocationTargetException ignored) {}
        }

        if (event != null) {
            if (applicationEventPublisher != null) {
                applicationEventPublisher.publishEvent(event);
            }
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("No event was found for the exception " + exception.getClass().getName());
            }
        }
    }

    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    /**
     * Sets additional exception to event mappings. These are automatically merged with the default
     * exception to event mappings that <code>ProviderManager</code> defines.
     *
     * @param additionalExceptionMappings where keys are the fully-qualified string name of the exception class and the
     * values are the fully-qualified string name of the event class to fire.
     */
    @SuppressWarnings({"unchecked"})
    public void setAdditionalExceptionMappings(Properties additionalExceptionMappings) {
        Assert.notNull(additionalExceptionMappings, "The exceptionMappings object must not be null");
        for(Object exceptionClass : additionalExceptionMappings.keySet()) {
            String eventClass = (String) additionalExceptionMappings.get(exceptionClass);
            try {
                Class<?> clazz = getClass().getClassLoader().loadClass(eventClass);
                Assert.isAssignable(AbstractAuthenticationFailureEvent.class, clazz);
                addMapping((String) exceptionClass, (Class<? extends AbstractAuthenticationFailureEvent>) clazz);
            } catch (ClassNotFoundException e) {
                throw new RuntimeException("Failed to load authentication event class " + eventClass);
            }
        }
    }

    private void addMapping(String exceptionClass,
                            Class<? extends AbstractAuthenticationFailureEvent> eventClass) {
        try {
            Constructor<? extends AbstractAuthenticationEvent> constructor =
                    eventClass.getConstructor(Authentication.class, AuthenticationException.class);
            exceptionMappings.put(exceptionClass, constructor);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException("Authentication event class " + eventClass.getName() + " has no suitable constructor");
        }
    }
}
