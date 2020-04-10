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
package org.springframework.security.config.annotation.web;

import static org.junit.Assert.*
import static org.springframework.security.config.annotation.web.WebSecurityConfigurerAdapterTestsConfigs.*

import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationListener
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.AnnotationAwareOrderComparator
import org.springframework.core.annotation.Order
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.AuthenticationTrustResolver
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.event.AuthenticationSuccessEvent
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter
import org.springframework.web.accept.ContentNegotiationStrategy
import org.springframework.web.accept.HeaderContentNegotiationStrategy
import org.springframework.web.filter.OncePerRequestFilter

/**
 * @author Rob Winch
 *
 */
class WebSecurityConfigurerAdapterTests extends BaseSpringSpec {

    def "MessageSources populated on AuthenticationProviders"() {
        when:
            loadConfig(MessageSourcesPopulatedConfig)
            List<AuthenticationProvider> providers = authenticationProviders()
        then:
            providers*.messages*.messageSource == [context,context,context,context]
    }

    def "messages set when using WebSecurityConfigurerAdapter"() {
        when:
            loadConfig(InMemoryAuthWithWebSecurityConfigurerAdapter)
        then:
            authenticationManager.messages.messageSource instanceof ApplicationContext
    }

    def "headers are populated by default"() {
        setup: "load config that overrides http and accepts defaults"
            loadConfig(HeadersArePopulatedByDefaultConfig)
            request.secure = true
        when: "invoke the springSecurityFilterChain"
            springSecurityFilterChain.doFilter(request, response, chain)
        then: "the default headers are added"
            responseHeaders == ['X-Content-Type-Options':'nosniff',
                         'X-Frame-Options':'DENY',
                         'Strict-Transport-Security': 'max-age=31536000 ; includeSubDomains',
                         'Cache-Control': 'no-cache, no-store, max-age=0, must-revalidate',
                         'Pragma':'no-cache',
                         'Expires' : '0',
                         'X-XSS-Protection' : '1; mode=block']
    }

    @EnableWebSecurity
    @Configuration
    static class HeadersArePopulatedByDefaultConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {

        }
    }

    def "webasync populated by default"() {
        when: "load config that overrides http and accepts defaults"
            loadConfig(WebAsyncPopulatedByDefaultConfig)
        then: "WebAsyncManagerIntegrationFilter is populated"
            findFilter(WebAsyncManagerIntegrationFilter)
    }

    @EnableWebSecurity
    @Configuration
    static class WebAsyncPopulatedByDefaultConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {

        }
    }

    def "AuthenticationEventPublisher is registered for Web configure(AuthenticationManagerBuilder auth)"() {
        when:
            loadConfig(InMemoryAuthWithWebSecurityConfigurerAdapter)
        then:
            authenticationManager.parent.eventPublisher instanceof DefaultAuthenticationEventPublisher
        when:
            Authentication token = new UsernamePasswordAuthenticationToken("user","password")
            authenticationManager.authenticate(token)
        then: "We only receive the AuthenticationSuccessEvent once"
            InMemoryAuthWithWebSecurityConfigurerAdapter.EVENTS.size() == 1
            InMemoryAuthWithWebSecurityConfigurerAdapter.EVENTS[0].authentication.name == token.principal
    }

    @EnableWebSecurity
    @Configuration
    static class InMemoryAuthWithWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter implements ApplicationListener<AuthenticationSuccessEvent> {
        static List<AuthenticationSuccessEvent> EVENTS = []
        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean()
                throws Exception {
            return super.authenticationManagerBean();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }

        @Override
        public void onApplicationEvent(AuthenticationSuccessEvent e) {
            EVENTS.add(e)
        }
    }

    def "Override ContentNegotiationStrategy with @Bean"() {
        setup:
            OverrideContentNegotiationStrategySharedObjectConfig.CNS = Mock(ContentNegotiationStrategy)
        when:
            loadConfig(OverrideContentNegotiationStrategySharedObjectConfig)
        then:
            context.getBean(OverrideContentNegotiationStrategySharedObjectConfig).http.getSharedObject(ContentNegotiationStrategy) == OverrideContentNegotiationStrategySharedObjectConfig.CNS
    }

    @EnableWebSecurity
    @Configuration
    static class OverrideContentNegotiationStrategySharedObjectConfig extends WebSecurityConfigurerAdapter {
        static ContentNegotiationStrategy CNS

        @Bean
        public ContentNegotiationStrategy cns() {
            return CNS
        }
    }

    def "ContentNegotiationStrategy shareObject defaults to Header with no @Bean"() {
        when:
            loadConfig(ContentNegotiationStrategyDefaultSharedObjectConfig)
        then:
            context.getBean(ContentNegotiationStrategyDefaultSharedObjectConfig).http.getSharedObject(ContentNegotiationStrategy).class == HeaderContentNegotiationStrategy
    }

    @EnableWebSecurity
    @Configuration
    static class ContentNegotiationStrategyDefaultSharedObjectConfig extends WebSecurityConfigurerAdapter {}

    def "UserDetailsService lazy"() {
        setup:
            loadConfig(RequiresUserDetailsServiceConfig,UserDetailsServiceConfig)
        when:
            findFilter(MyFilter).userDetailsService.loadUserByUsername("user")
        then:
            noExceptionThrown()
        when:
            findFilter(MyFilter).userDetailsService.loadUserByUsername("admin")
        then:
            thrown(UsernameNotFoundException)
    }

    @Configuration
    static class RequiresUserDetailsServiceConfig {
        @Bean
        public MyFilter myFilter(UserDetailsService uds) {
            return new MyFilter(uds)
        }
    }

    @Configuration
    @EnableWebSecurity
    static class UserDetailsServiceConfig extends WebSecurityConfigurerAdapter {
        @Autowired
        private MyFilter myFilter;

        @Bean
        @Override
        public UserDetailsService userDetailsServiceBean() {
            return super.userDetailsServiceBean()
        }

        @Override
        public void configure(HttpSecurity http) {
            http
                .addFilterBefore(myFilter,UsernamePasswordAuthenticationFilter)
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
        }
    }

    def "SEC-2274: WebSecurityConfigurer adds ApplicationContext as a shared object"() {
        when:
            loadConfig(ApplicationContextSharedObjectConfig)
        then:
            context.getBean(ApplicationContextSharedObjectConfig).http.getSharedObject(ApplicationContext) == context
    }

    @Configuration
    @EnableWebSecurity
    static class ApplicationContextSharedObjectConfig extends WebSecurityConfigurerAdapter {

    }

    static class MyFilter extends OncePerRequestFilter {
        private UserDetailsService userDetailsService
        public MyFilter(UserDetailsService uds) {
            assert uds != null
            this.userDetailsService = uds
        }
        public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
            chain.doFilter(request,response)
        }
    }

    def "AuthenticationTrustResolver populated as defaultObject"() {
        setup:
            CustomTrustResolverConfig.TR = Mock(AuthenticationTrustResolver)
        when:
            loadConfig(CustomTrustResolverConfig)
        then:
            context.getBean(CustomTrustResolverConfig).http.getSharedObject(AuthenticationTrustResolver) == CustomTrustResolverConfig.TR
    }

    @Configuration
    @EnableWebSecurity
    static class CustomTrustResolverConfig extends WebSecurityConfigurerAdapter {
        static AuthenticationTrustResolver TR

        @Bean
        public AuthenticationTrustResolver tr() {
            return TR
        }
    }

    def "WebSecurityConfigurerAdapter has Ordered between 0 and lowest priority"() {
        when:
            def lowestConfig = new LowestPriorityWebSecurityConfig()
            def defaultConfig = new DefaultOrderWebSecurityConfig()
            def compare = new AnnotationAwareOrderComparator()
        then: "the default ordering is between 0 and lowest priority (Boot adapters)"
            compare.compare(lowestConfig, defaultConfig) > 0
    }

    class DefaultOrderWebSecurityConfig extends WebSecurityConfigurerAdapter {}

    @Order(Ordered.LOWEST_PRECEDENCE)
    class LowestPriorityWebSecurityConfig extends WebSecurityConfigurerAdapter {}
}
