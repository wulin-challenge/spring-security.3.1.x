/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.config.ldap;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.config.ldap.LdapUserServiceBeanDefinitionParser.*;

import org.junit.*;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.ldap.userdetails.InetOrgPersonContextMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.ldap.userdetails.Person;
import org.springframework.security.ldap.userdetails.PersonContextMapper;
import org.w3c.dom.Element;

import java.util.*;

/**
 * @author Luke Taylor
 * @author Rob Winch
 */
public class LdapUserServiceBeanDefinitionParserTests {
    private InMemoryXmlApplicationContext appCtx;

    @After
    public void closeAppContext() {
        if (appCtx != null) {
            appCtx.close();
            appCtx = null;
        }
    }

    @Test
    public void beanClassNamesAreCorrect() throws Exception {
        assertEquals(LDAP_SEARCH_CLASS, FilterBasedLdapUserSearch.class.getName());
        assertEquals(PERSON_MAPPER_CLASS, PersonContextMapper.class.getName());
        assertEquals(INET_ORG_PERSON_MAPPER_CLASS, InetOrgPersonContextMapper.class.getName());
        assertEquals(LDAP_USER_MAPPER_CLASS, LdapUserDetailsMapper.class.getName());
        assertEquals(LDAP_AUTHORITIES_POPULATOR_CLASS, DefaultLdapAuthoritiesPopulator.class.getName());
        assertEquals(LdapUserDetailsService.class.getName(), new LdapUserServiceBeanDefinitionParser().getBeanClassName(mock(Element.class)));
    }

    @Test
    public void minimalConfigurationIsParsedOk() throws Exception {
        setContext("<ldap-user-service user-search-filter='(uid={0})' /><ldap-server ldif='classpath:test-server.ldif' url='ldap://127.0.0.1:343/dc=springframework,dc=org' />");
    }

    @Test
    public void userServiceReturnsExpectedData() throws Exception {
        setContext("<ldap-user-service id='ldapUDS' user-search-filter='(uid={0})' group-search-filter='member={0}' /><ldap-server ldif='classpath:test-server.ldif'/>");

        UserDetailsService uds = (UserDetailsService) appCtx.getBean("ldapUDS");
        UserDetails ben = uds.loadUserByUsername("ben");

        Set<String> authorities = AuthorityUtils.authorityListToSet(ben.getAuthorities());
        assertEquals(3, authorities.size());
        assertTrue(authorities.contains("ROLE_DEVELOPERS"));
    }

    @Test
    public void differentUserSearchBaseWorksAsExpected() throws Exception {
        setContext("<ldap-user-service id='ldapUDS' " +
                "       user-search-base='ou=otherpeople' " +
                "       user-search-filter='(cn={0})' " +
                "       group-search-filter='member={0}' /><ldap-server ldif='classpath:test-server.ldif'/>");

        UserDetailsService uds = (UserDetailsService) appCtx.getBean("ldapUDS");
        UserDetails joe = uds.loadUserByUsername("Joe Smeth");

        assertEquals("Joe Smeth", joe.getUsername());
    }

    @Test
    public void rolePrefixIsSupported() throws Exception {
        setContext(
                "<ldap-user-service id='ldapUDS' " +
                "     user-search-filter='(uid={0})' " +
                "     group-search-filter='member={0}' role-prefix='PREFIX_'/>" +
                "<ldap-user-service id='ldapUDSNoPrefix' " +
                "     user-search-filter='(uid={0})' " +
                "     group-search-filter='member={0}' role-prefix='none'/><ldap-server ldif='classpath:test-server.ldif'/>");

        UserDetailsService uds = (UserDetailsService) appCtx.getBean("ldapUDS");
        UserDetails ben = uds.loadUserByUsername("ben");
        assertTrue(AuthorityUtils.authorityListToSet(ben.getAuthorities()).contains("PREFIX_DEVELOPERS"));

        uds = (UserDetailsService) appCtx.getBean("ldapUDSNoPrefix");
        ben = uds.loadUserByUsername("ben");
        assertTrue(AuthorityUtils.authorityListToSet(ben.getAuthorities()).contains("DEVELOPERS"));
    }



    @Test
    public void differentGroupRoleAttributeWorksAsExpected() throws Exception {
        setContext("<ldap-user-service id='ldapUDS' user-search-filter='(uid={0})' group-role-attribute='ou' group-search-filter='member={0}' /><ldap-server ldif='classpath:test-server.ldif'/>");

        UserDetailsService uds = (UserDetailsService) appCtx.getBean("ldapUDS");
        UserDetails ben = uds.loadUserByUsername("ben");

        Set<String> authorities = AuthorityUtils.authorityListToSet(ben.getAuthorities());
        assertEquals(3, authorities.size());
        assertTrue(authorities.contains("ROLE_DEVELOPER"));

    }

    @Test
    public void isSupportedByAuthenticationProviderElement() {
        setContext(
                "<ldap-server url='ldap://127.0.0.1:343/dc=springframework,dc=org' ldif='classpath:test-server.ldif'/>" +
                "<authentication-manager>" +
                "  <authentication-provider>" +
                "    <ldap-user-service user-search-filter='(uid={0})' />" +
                "  </authentication-provider>" +
                "</authentication-manager>");
    }

    @Test
    public void personContextMapperIsSupported() {
        setContext(
                "<ldap-server ldif='classpath:test-server.ldif'/>" +
                "<ldap-user-service id='ldapUDS' user-search-filter='(uid={0})' user-details-class='person'/>");
        UserDetailsService uds = (UserDetailsService) appCtx.getBean("ldapUDS");
        UserDetails ben = uds.loadUserByUsername("ben");
        assertTrue(ben instanceof Person);
    }

    @Test
    public void inetOrgContextMapperIsSupported() {
        setContext(
                "<ldap-server id='someServer' ldif='classpath:test-server.ldif'/>" +
                "<ldap-user-service id='ldapUDS' user-search-filter='(uid={0})' user-details-class='inetOrgPerson'/>");
        UserDetailsService uds = (UserDetailsService) appCtx.getBean("ldapUDS");
        UserDetails ben = uds.loadUserByUsername("ben");
        assertTrue(ben instanceof InetOrgPerson);
    }

    @Test
    public void externalContextMapperIsSupported() {
        setContext(
                "<ldap-server id='someServer' ldif='classpath:test-server.ldif'/>" +
                "<ldap-user-service id='ldapUDS' user-search-filter='(uid={0})' user-context-mapper-ref='mapper'/>" +
                "<b:bean id='mapper' class='"+ InetOrgPersonContextMapper.class.getName() +"'/>");

        UserDetailsService uds = (UserDetailsService) appCtx.getBean("ldapUDS");
        UserDetails ben = uds.loadUserByUsername("ben");
        assertTrue(ben instanceof InetOrgPerson);
    }


    private void setContext(String context) {
        appCtx = new InMemoryXmlApplicationContext(context);
    }
}
