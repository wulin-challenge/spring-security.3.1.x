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
package org.springframework.security.config.annotation.web.configuration;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;

/**
 * Add this annotation to an {@code @Configuration} class to have the Spring Security
 * configuration defined in any {@link WebSecurityConfigurer} or more likely by extending the
 * {@link WebSecurityConfigurerAdapter} base class and overriding individual methods:
 * 
 * <p> 将此注释添加到@Configuration类中，以在任何WebSecurityConfigurer中定义
 * Spring Security配置，或者更可能通过扩展WebSecurityConfigurerAdapter基类并覆盖各个方法来定义：
 * 
 *
 * <pre class="code">
 * &#064;Configuration
 * &#064;EnableWebSecurity
 * public class MyWebSecurityConfiguration extends WebSecurityConfigurerAdapter {
 *
 *    &#064;Override
 *    public void configure(WebSecurity web) throws Exception {
 *        web
 *            .ignoring()
 *                // Spring Security should completely ignore URLs starting with /resources/
 *                .antMatchers("/resources/**");
 *    }
 *
 *    &#064;Override
 *    protected void configure(HttpSecurity http) throws Exception {
 *        http
 *            .authorizeRequests()
 *                .antMatchers("/public/**").permitAll()
 *                .anyRequest().hasRole("USER")
 *                .and()
 *            // Possibly more configuration ...
 *            .formLogin() // enable form based log in
 *                // set permitAll for all URLs associated with Form Login
 *               .permitAll();
 *    }
 *
 *    &#064;Override
 *    protected void configure(AuthenticationManagerBuilder auth) {
 *        auth
 *            // enable in memory based authentication with a user named "user" and "admin"
 *            .inMemoryAuthentication()
 *                .withUser("user").password("password").roles("USER").and()
 *                .withUser("admin").password("password").roles("USER", "ADMIN");
 *    }
 *
 *    // Possibly more overridden methods ...
 * }
 * </pre>
 *
 * @see WebSecurityConfigurer
 * @see WebSecurityConfigurerAdapter
 *
 * @author Rob Winch
 * @since 3.2
 */
@Retention(value=java.lang.annotation.RetentionPolicy.RUNTIME)
@Target(value={java.lang.annotation.ElementType.TYPE})
@Documented
@Import({WebSecurityConfiguration.class,ObjectPostProcessorConfiguration.class})
@EnableGlobalAuthentication
public @interface EnableWebSecurity {

    /**
     * Controls debugging support for Spring Security. Default is false.
     * 
     * <p> 控制对Spring Security的调试支持。 默认为false。
     * 
     * @return if true, enables debug support with Spring Security
     * 
     * <p> 如果为true，则启用Spring Security的调试支持
     */
    boolean debug() default false;
}