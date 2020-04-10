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

package org.springframework.security.web;

import junit.framework.TestCase;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.web.PortMapperImpl;


/**
 * Tests {@link PortMapperImpl}.
 *
 * @author Ben Alex
 */
public class PortMapperImplTests extends TestCase {
    //~ Methods ========================================================================================================

    public void testDefaultMappingsAreKnown() throws Exception {
        PortMapperImpl portMapper = new PortMapperImpl();
        assertEquals(Integer.valueOf(80), portMapper.lookupHttpPort(Integer.valueOf(443)));
        assertEquals(Integer.valueOf(8080), portMapper.lookupHttpPort(Integer.valueOf(8443)));
        assertEquals(Integer.valueOf(443), portMapper.lookupHttpsPort(Integer.valueOf(80)));
        assertEquals(Integer.valueOf(8443), portMapper.lookupHttpsPort(Integer.valueOf(8080)));
    }

    public void testDetectsEmptyMap() throws Exception {
        PortMapperImpl portMapper = new PortMapperImpl();

        try {
            portMapper.setPortMappings(new HashMap<String,String>());
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testDetectsNullMap() throws Exception {
        PortMapperImpl portMapper = new PortMapperImpl();

        try {
            portMapper.setPortMappings(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGetTranslatedPortMappings() {
        PortMapperImpl portMapper = new PortMapperImpl();
        assertEquals(2, portMapper.getTranslatedPortMappings().size());
    }

    public void testRejectsOutOfRangeMappings() {
        PortMapperImpl portMapper = new PortMapperImpl();
        Map<String, String> map = new HashMap<String, String>();
        map.put("79", "80559");

        try {
            portMapper.setPortMappings(map);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testReturnsNullIfHttpPortCannotBeFound() {
        PortMapperImpl portMapper = new PortMapperImpl();
        assertTrue(portMapper.lookupHttpPort(Integer.valueOf("34343")) == null);
    }

    public void testSupportsCustomMappings() {
        PortMapperImpl portMapper = new PortMapperImpl();
        Map<String, String> map = new HashMap<String, String>();
        map.put("79", "442");

        portMapper.setPortMappings(map);

        assertEquals(Integer.valueOf(79), portMapper.lookupHttpPort(Integer.valueOf(442)));
        assertEquals(Integer.valueOf(442), portMapper.lookupHttpsPort(Integer.valueOf(79)));
    }
}
