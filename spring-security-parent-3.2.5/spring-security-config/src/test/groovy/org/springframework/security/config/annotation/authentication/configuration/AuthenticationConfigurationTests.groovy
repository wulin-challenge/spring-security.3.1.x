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
package org.springframework.security.config.annotation.authentication.configuration;

import org.springframework.aop.framework.ProxyFactoryBean
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.access.annotation.Secured
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter
import org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.provisioning.InMemoryUserDetailsManager

class AuthenticationConfigurationTests extends BaseSpringSpec {

    def "Ordering Autowired on EnableGlobalMethodSecurity"() {
        setup:
            SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", "password","ROLE_USER"))
        when:
            loadConfig(GlobalMethodSecurityAutowiredConfigAndServicesConfig)
        then:
            context.getBean(Service).run()
    }

    @Configuration
    @Import([GlobalMethodSecurityAutowiredConfig,ServicesConfig])
    static class GlobalMethodSecurityAutowiredConfigAndServicesConfig {}

    @Configuration
    @EnableGlobalMethodSecurity(securedEnabled = true)
    static class GlobalMethodSecurityAutowiredConfig {
        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) {
            auth.inMemoryAuthentication().withUser("user").password("password").roles("USER")
        }
    }

    def "Ordering Autowired on EnableWebSecurity"() {
        setup:
            SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", "password","ROLE_USER"))
        when:
            loadConfig(GlobalMethodSecurityConfigAndServicesConfig)
        then:
            context.getBean(Service).run()
    }

    @Configuration
    @Import([GlobalMethodSecurityConfig,WebSecurityConfig,ServicesConfig])
    static class GlobalMethodSecurityConfigAndServicesConfig {}

    @Configuration
    @EnableGlobalMethodSecurity(securedEnabled = true)
    static class GlobalMethodSecurityConfig {}

    @Configuration
    @EnableWebSecurity
    static class WebSecurityConfig extends WebSecurityConfigurerAdapter {
        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) {
            auth.inMemoryAuthentication().withUser("user").password("password").roles("USER")
        }
    }

    //

    def "Ordering Autowired on EnableWebMvcSecurity"() {
        setup:
            SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", "password","ROLE_USER"))
        when:
            loadConfig(GlobalMethodSecurityMvcSecurityAndServicesConfig)
        then:
            context.getBean(Service).run()
    }

    @Configuration
    @Import([GlobalMethodSecurityConfig,WebMvcSecurityConfig,ServicesConfig])
    static class GlobalMethodSecurityMvcSecurityAndServicesConfig {}

    @Configuration
    @EnableWebMvcSecurity
    static class WebMvcSecurityConfig extends WebSecurityConfigurerAdapter {
        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) {
            auth.inMemoryAuthentication().withUser("user").password("password").roles("USER")
        }
    }

    //

    def "no authentication getAuthenticationManager falls back to null"() {
        when:
            loadConfig(AuthenticationConfiguration,ObjectPostProcessorConfiguration)
        then:
            context.getBean(AuthenticationConfiguration).authenticationManager == null
    }

    def "QuiesentGlobalAuthenticationConfiguererAdapter falls back to null"() {
        when:
            loadConfig(AuthenticationConfiguration,ObjectPostProcessorConfiguration,QuiesentGlobalAuthenticationConfiguererAdapter)
        then:
            context.getBean(AuthenticationConfiguration).authenticationManager == null
    }

    @Configuration
    static class QuiesentGlobalAuthenticationConfiguererAdapter extends GlobalAuthenticationConfigurerAdapter {}

    //

    def "GlobalAuthenticationConfiguererAdapterImpl configures authentication successfully"() {
        setup:
            def token = new UsernamePasswordAuthenticationToken("user", "password")
        when:
            loadConfig(AuthenticationConfiguration,ObjectPostProcessorConfiguration,GlobalAuthenticationConfiguererAdapterImpl)
        then:
            context.getBean(AuthenticationConfiguration).authenticationManager.authenticate(token)?.name == "user"
    }

    @Configuration
    static class GlobalAuthenticationConfiguererAdapterImpl extends GlobalAuthenticationConfigurerAdapter {
        public void init(AuthenticationManagerBuilder auth) throws Exception {
            auth.inMemoryAuthentication().withUser("user").password("password").roles("USER")
        }
    }

    //

    def "AuthenticationManagerBean configures authentication successfully"() {
        setup:
            def token = new UsernamePasswordAuthenticationToken("user", "password")
            def auth = new UsernamePasswordAuthenticationToken("user", "password", AuthorityUtils.createAuthorityList("ROLE_USER"))
            AuthenticationManagerBeanConfig.AM = Mock(AuthenticationManager)
            1 * AuthenticationManagerBeanConfig.AM.authenticate(token) >> auth
        when:
            loadConfig(AuthenticationConfiguration,ObjectPostProcessorConfiguration,AuthenticationManagerBeanConfig)
        then:
            context.getBean(AuthenticationConfiguration).authenticationManager.authenticate(token).name == auth.name
    }

    @Configuration
    static class AuthenticationManagerBeanConfig {
        static AuthenticationManager AM
        @Bean
        public AuthenticationManager authenticationManager() {
            AM
        }
    }

    //

    @Configuration
    static class ServicesConfig {
        @Bean
        public Service service() {
            return new ServiceImpl()
        }
    }

    static interface Service {
        public void run();
    }

    static class ServiceImpl implements Service {
        @Secured("ROLE_USER")
        public void run() {}
    }

    //

    def "GlobalAuthenticationConfigurerAdapter are ordered"() {
        setup:
            loadConfig(AuthenticationConfiguration,ObjectPostProcessorConfiguration)
            AuthenticationConfiguration config = context.getBean(AuthenticationConfiguration)
            config.setGlobalAuthenticationConfigurers([new LowestOrderGlobalAuthenticationConfigurerAdapter(), new HighestOrderGlobalAuthenticationConfigurerAdapter(), new DefaultOrderGlobalAuthenticationConfigurerAdapter()])
        when:
            config.getAuthenticationManager()
        then:
            DefaultOrderGlobalAuthenticationConfigurerAdapter.inits == [HighestOrderGlobalAuthenticationConfigurerAdapter,DefaultOrderGlobalAuthenticationConfigurerAdapter,LowestOrderGlobalAuthenticationConfigurerAdapter]
            DefaultOrderGlobalAuthenticationConfigurerAdapter.configs == [HighestOrderGlobalAuthenticationConfigurerAdapter,DefaultOrderGlobalAuthenticationConfigurerAdapter,LowestOrderGlobalAuthenticationConfigurerAdapter]

    }

    static class DefaultOrderGlobalAuthenticationConfigurerAdapter extends GlobalAuthenticationConfigurerAdapter {
        static List inits = []
        static List configs = []

        public void init(AuthenticationManagerBuilder auth) throws Exception {
            inits.add(getClass())
        }

        public void configure(AuthenticationManagerBuilder auth) throws Exception {
            configs.add(getClass())
        }
    }

    @Order(Ordered.LOWEST_PRECEDENCE)
    static class LowestOrderGlobalAuthenticationConfigurerAdapter extends DefaultOrderGlobalAuthenticationConfigurerAdapter {}

    @Order(Ordered.HIGHEST_PRECEDENCE)
    static class HighestOrderGlobalAuthenticationConfigurerAdapter extends DefaultOrderGlobalAuthenticationConfigurerAdapter {}

    //

    def "Spring Boot not triggered when already configured"() {
        setup:
            loadConfig(AuthenticationConfiguration,ObjectPostProcessorConfiguration)
            AuthenticationConfiguration config = context.getBean(AuthenticationConfiguration)
            config.setGlobalAuthenticationConfigurers([new ConfiguresInMemoryConfigurerAdapter(), new BootGlobalAuthenticationConfigurerAdapter()])
            AuthenticationManager authenticationManager = config.authenticationManager
        when:
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user","password"))
        then:
            noExceptionThrown()
        when:
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("boot","password"))
        then:
            thrown(AuthenticationException)
    }


    def "Spring Boot is triggered when not already configured"() {
        setup:
            loadConfig(AuthenticationConfiguration,ObjectPostProcessorConfiguration)
            AuthenticationConfiguration config = context.getBean(AuthenticationConfiguration)
            config.setGlobalAuthenticationConfigurers([new BootGlobalAuthenticationConfigurerAdapter()])
            AuthenticationManager authenticationManager = config.authenticationManager
        when:
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("boot","password"))
        then:
            noExceptionThrown()
    }

    static class ConfiguresInMemoryConfigurerAdapter extends GlobalAuthenticationConfigurerAdapter {

        public void init(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }
    }

    @Order(Ordered.LOWEST_PRECEDENCE)
    static class BootGlobalAuthenticationConfigurerAdapter extends DefaultOrderGlobalAuthenticationConfigurerAdapter {
        public void init(AuthenticationManagerBuilder auth) throws Exception {
            auth.apply(new DefaultBootGlobalAuthenticationConfigurerAdapter())
        }
    }

    static class DefaultBootGlobalAuthenticationConfigurerAdapter extends DefaultOrderGlobalAuthenticationConfigurerAdapter {
        @Override
        public void configure(AuthenticationManagerBuilder auth) throws Exception {
            if(auth.isConfigured()) {
                return;
            }

            User user = new User("boot","password", AuthorityUtils.createAuthorityList("ROLE_USER"))

            List<User> users = Arrays.asList(user);
            InMemoryUserDetailsManager inMemory = new InMemoryUserDetailsManager(users);

            DaoAuthenticationProvider provider = new DaoAuthenticationProvider()
            provider.userDetailsService = inMemory

            auth.authenticationProvider(provider)
        }
    }

    def "SEC-2531: AuthenticationConfiguration#lazyBean should use BeanClassLoader on ProxyFactoryBean"() {
        setup:
            ObjectPostProcessor opp = Mock()
            Sec2531Config. opp = opp
            loadConfig(Sec2531Config)
        when:
            AuthenticationConfiguration config = context.getBean(AuthenticationConfiguration)
            config.getAuthenticationManager()
        then:
            1 * opp.postProcess(_ as ProxyFactoryBean) >> { args ->
                args[0]
            }
    }

    @Configuration
    @Import(AuthenticationConfiguration)
    static class Sec2531Config {
        static ObjectPostProcessor opp

        @Bean
        public ObjectPostProcessor objectPostProcessor() {
            opp
        }

        @Bean
        public AuthenticationManager manager() {
            null
        }
    }
}