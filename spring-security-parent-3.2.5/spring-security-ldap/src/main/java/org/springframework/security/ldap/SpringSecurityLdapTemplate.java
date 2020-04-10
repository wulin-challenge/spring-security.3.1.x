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
package org.springframework.security.ldap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.ContextExecutor;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.util.Assert;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;


/**
 * Extension of Spring LDAP's LdapTemplate class which adds extra functionality required by Spring Security.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @since 2.0
 */
public class SpringSecurityLdapTemplate extends LdapTemplate {
    //~ Static fields/initializers =====================================================================================
    private static final Log logger = LogFactory.getLog(SpringSecurityLdapTemplate.class);

    public static final String[] NO_ATTRS = new String[0];
    private static final boolean RETURN_OBJECT = true;

    //~ Instance fields ================================================================================================

    /** Default search controls */
    private SearchControls searchControls = new SearchControls();

    //~ Constructors ===================================================================================================

    public SpringSecurityLdapTemplate(ContextSource contextSource) {
        Assert.notNull(contextSource, "ContextSource cannot be null");
        setContextSource(contextSource);

        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    }

    //~ Methods ========================================================================================================

    /**
     * Performs an LDAP compare operation of the value of an attribute for a particular directory entry.
     *
     * @param dn the entry who's attribute is to be used
     * @param attributeName the attribute who's value we want to compare
     * @param value the value to be checked against the directory value
     *
     * @return true if the supplied value matches that in the directory
     */
    public boolean compare(final String dn, final String attributeName, final Object value) {
        final String comparisonFilter = "(" + attributeName + "={0})";

        class LdapCompareCallback implements ContextExecutor {

            public Object executeWithContext(DirContext ctx) throws NamingException {
                SearchControls ctls = new SearchControls();
                ctls.setReturningAttributes(NO_ATTRS);
                ctls.setSearchScope(SearchControls.OBJECT_SCOPE);

                NamingEnumeration<SearchResult> results = ctx.search(dn, comparisonFilter, new Object[] {value}, ctls);

                Boolean match = Boolean.valueOf(results.hasMore());
                LdapUtils.closeEnumeration(results);

                return match;
            }
        }

        Boolean matches = (Boolean) executeReadOnly(new LdapCompareCallback());

        return matches.booleanValue();
    }

    /**
     * Composes an object from the attributes of the given DN.
     *
     * @param dn the directory entry which will be read
     * @param attributesToRetrieve the named attributes which will be retrieved from the directory entry.
     *
     * @return the object created by the mapper
     */
    public DirContextOperations retrieveEntry(final String dn, final String[] attributesToRetrieve) {

        return (DirContextOperations) executeReadOnly(new ContextExecutor() {
                public Object executeWithContext(DirContext ctx) throws NamingException {
                    Attributes attrs = ctx.getAttributes(dn, attributesToRetrieve);

                    // Object object = ctx.lookup(LdapUtils.getRelativeName(dn, ctx));

                    return new DirContextAdapter(attrs, new DistinguishedName(dn),
                            new DistinguishedName(ctx.getNameInNamespace()));
                }
            });
    }

    /**
     * Performs a search using the supplied filter and returns the union of the values of the named attribute
     * found in all entries matched by the search. Note that one directory entry may have several values for the
     * attribute. Intended for role searches and similar scenarios.
     *
     * @param base the DN to search in
     * @param filter search filter to use
     * @param params the parameters to substitute in the search filter
     * @param attributeName the attribute who's values are to be retrieved.
     *
     * @return the set of String values for the attribute as a union of the values found in all the matching entries.
     */
    public Set<String> searchForSingleAttributeValues(final String base, final String filter, final Object[] params,
            final String attributeName) {
        // Escape the params acording to RFC2254
        Object[] encodedParams = new String[params.length];

        for (int i=0; i < params.length; i++) {
            encodedParams[i] = LdapEncoder.filterEncode(params[i].toString());
        }

        String formattedFilter = MessageFormat.format(filter, encodedParams);
        logger.debug("Using filter: " + formattedFilter);

        final HashSet<String> set = new HashSet<String>();

        ContextMapper roleMapper = new ContextMapper() {
            public Object mapFromContext(Object ctx) {
                DirContextAdapter adapter = (DirContextAdapter) ctx;
                String[] values = adapter.getStringAttributes(attributeName);
                if (values == null || values.length == 0) {
                    logger.debug("No attribute value found for '" + attributeName + "'");
                } else {
                    set.addAll(Arrays.asList(values));
                }
                return null;
            }
        };

        SearchControls ctls = new SearchControls();
        ctls.setSearchScope(searchControls.getSearchScope());
        ctls.setReturningAttributes(new String[] {attributeName});

        search(base, formattedFilter, ctls, roleMapper);

        return set;
    }

    /**
     * Performs a search, with the requirement that the search shall return a single directory entry, and uses
     * the supplied mapper to create the object from that entry.
     * <p>
     * Ignores <tt>PartialResultException</tt> if thrown, for compatibility with Active Directory
     * (see {@link LdapTemplate#setIgnorePartialResultException(boolean)}).
     *
     * @param base the search base, relative to the base context supplied by the context source.
     * @param filter the LDAP search filter
     * @param params parameters to be substituted in the search.
     *
     * @return a DirContextOperations instance created from the matching entry.
     *
     * @throws IncorrectResultSizeDataAccessException if no results are found or the search returns more than one
     *         result.
     */
    public DirContextOperations searchForSingleEntry(final String base, final String filter, final Object[] params) {

        return (DirContextOperations) executeReadOnly(new ContextExecutor() {
                public Object executeWithContext(DirContext ctx) throws NamingException {
                    return searchForSingleEntryInternal(ctx, searchControls, base, filter, params);
                }
        });
    }

    /**
     * Internal method extracted to avoid code duplication in AD search.
     */
    public static DirContextOperations searchForSingleEntryInternal(DirContext ctx, SearchControls searchControls,
            String base, String filter, Object[] params) throws NamingException {
        final DistinguishedName ctxBaseDn = new DistinguishedName(ctx.getNameInNamespace());
        final DistinguishedName searchBaseDn = new DistinguishedName(base);
        final NamingEnumeration<SearchResult> resultsEnum = ctx.search(searchBaseDn, filter, params, buildControls(searchControls));

        if (logger.isDebugEnabled()) {
            logger.debug("Searching for entry under DN '" + ctxBaseDn
                    + "', base = '" + searchBaseDn + "', filter = '" + filter + "'");
        }

        Set<DirContextOperations> results = new HashSet<DirContextOperations>();
        try {
            while (resultsEnum.hasMore()) {
                SearchResult searchResult = resultsEnum.next();
                DirContextAdapter dca = (DirContextAdapter) searchResult.getObject();
                Assert.notNull(dca, "No object returned by search, DirContext is not correctly configured");

                if (logger.isDebugEnabled()) {
                    logger.debug("Found DN: " + dca.getDn());
                }
                results.add(dca);
            }
        } catch (PartialResultException e) {
            LdapUtils.closeEnumeration(resultsEnum);
            logger.info("Ignoring PartialResultException");
        }

        if (results.size() == 0) {
            throw new IncorrectResultSizeDataAccessException(1, 0);
        }

        if (results.size() > 1) {
            throw new IncorrectResultSizeDataAccessException(1, results.size());
        }

        return results.iterator().next();
    }

    /**
     * We need to make sure the search controls has the return object flag set to true, in order for
     * the search to return DirContextAdapter instances.
     * @param originalControls
     * @return
     */
    private static SearchControls buildControls(SearchControls originalControls) {
        return new SearchControls(originalControls.getSearchScope(),
                originalControls.getCountLimit(),
                originalControls.getTimeLimit(),
                originalControls.getReturningAttributes(),
                RETURN_OBJECT,
                originalControls.getDerefLinkFlag());
    }

    /**
     * Sets the search controls which will be used for search operations by the template.
     *
     * @param searchControls the SearchControls instance which will be cached in the template.
     */
    public void setSearchControls(SearchControls searchControls) {
        this.searchControls = searchControls;
    }
}
