/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.core.userdetails.memory;

import junit.framework.TestCase;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.*;


/**
 * Tests {@link InMemoryDaoImpl}.
 *
 * @author Ben Alex
 */
@SuppressWarnings({"deprecation"})
public class InMemoryDaoTests extends TestCase {

    //~ Methods ========================================================================================================

    private UserMap makeUserMap() {
        UserMapEditor editor = new UserMapEditor();
        editor.setAsText("rod=koala,ROLE_ONE,ROLE_TWO,enabled\nScott=wombat,ROLE_ONE,ROLE_TWO,enabled");

        return (UserMap) editor.getValue();
    }

    public void testLookupFails() throws Exception {
        InMemoryDaoImpl dao = new InMemoryDaoImpl();
        dao.setUserMap(makeUserMap());
        dao.afterPropertiesSet();

        try {
            dao.loadUserByUsername("UNKNOWN_USER");
            fail("Should have thrown UsernameNotFoundException");
        } catch (UsernameNotFoundException expected) {
            assertTrue(true);
        }
    }

    public void testLookupSuccess() throws Exception {
        InMemoryDaoImpl dao = new InMemoryDaoImpl();
        dao.setUserMap(makeUserMap());
        dao.afterPropertiesSet();
        assertEquals("koala", dao.loadUserByUsername("rod").getPassword());
        assertEquals("wombat", dao.loadUserByUsername("scott").getPassword());
    }

    public void testLookupSuccessWithMixedCase() throws Exception {
        InMemoryDaoImpl dao = new InMemoryDaoImpl();
        dao.setUserMap(makeUserMap());
        dao.afterPropertiesSet();
        assertEquals("koala", dao.loadUserByUsername("rod").getPassword());
        assertEquals("wombat", dao.loadUserByUsername("ScOTt").getPassword());
    }

    public void testStartupFailsIfUserMapNotSet() throws Exception {
        InMemoryDaoImpl dao = new InMemoryDaoImpl();

        try {
            dao.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupFailsIfUserMapSetToNull() throws Exception {
        InMemoryDaoImpl dao = new InMemoryDaoImpl();
        dao.setUserMap(null);

        try {
            dao.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupSuccessIfUserMapSet() throws Exception {
        InMemoryDaoImpl dao = new InMemoryDaoImpl();
        dao.setUserMap(makeUserMap());
        dao.afterPropertiesSet();
        assertEquals(2, dao.getUserMap().getUserCount());
    }

    public void testUseOfExternalPropertiesObject() throws Exception {
        InMemoryDaoImpl dao = new InMemoryDaoImpl();
        Properties props = new Properties();
        props.put("rod", "koala,ROLE_ONE,ROLE_TWO,enabled");
        props.put("scott", "wombat,ROLE_ONE,ROLE_TWO,enabled");
        dao.setUserProperties(props);
        assertEquals("koala", dao.loadUserByUsername("rod").getPassword());
        assertEquals("wombat", dao.loadUserByUsername("scott").getPassword());
    }
}
