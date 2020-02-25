/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.util.javascript;

/**
 * This class contains definitions of various HTML markup payloads, containing JavaScript definitions,
 * used to verify the proper work of HTML markup escaping in FreeMarker, AngularJS, and React libraries.
 *
 * @author <a href="mailto:jlieskov@redhat.com">Jan Lieskovsky</a>
 */

import org.apache.commons.lang.StringEscapeUtils;

public class JavascriptPayloadProvider {

    public class JSEquippedHTMLTagConstants {
        public final static String HTML_ATAG_JS_DOC_COOKIE = "<a href=\"#\" onclick=\"script:alert(document.cookie);\">Click me!</a>";
        public final static String HTML_SVGTAG_JS_CUSTOM = "<svg onload=\"script:alert(1);\"/>";
    }

    public static String escapeHtmlExceptDoubleQuotes(String input) {
        // AngularJS seems to omit double quotes by HTML markup escaping, emulate such output
        return StringEscapeUtils.escapeHtml(input).replace("&quot;", "\"");
    }

}
