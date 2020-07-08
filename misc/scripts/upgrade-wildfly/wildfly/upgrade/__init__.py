#
# Copyright 2020 Red Hat, Inc. and/or its affiliates
# and other contributors as indicated by the @author tags.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#

"""
Keycloak package for Python to assists with upgrading of Keycloak to
particular Wildfly tag / release.

Copyright 2020 Red Hat, Inc. and/or its affiliates
and other contributors as indicated by the @author tags.

To use, simply 'import wildfly.upgrade' and call the necessary routines.
"""

import itertools, logging, os, os.path, re, sys

from lxml import etree as et
from packaging import version
from shutil import copyfileobj
from subprocess import check_call, check_output
from tempfile import NamedTemporaryFile
from urllib.request import HTTPError, urlopen

__all__ = [
    'getElementsByXPath',
    'getKeycloakGitRepositoryRoot',
    'getPomDependencyByArtifactId',
    'getPomProperty',
    'getVersionOfPomDependency',
    'getXmlRoot',
    'isWellFormedWildflyTag',
    'saveUrlToNamedTemporaryFile'
    'updateAdapterLicenseFile',
    ' updateMainKeycloakPomFile'
]

__author__  = "Jan Lieskovsky <jlieskov@redhat.com>"
__status__  = "Alpha"
__version__ = "0.0.1"

#
# Various data structures for the module
#

# 'pom' namespace prefix definition for lxml
_pom_ns = "http://maven.apache.org/POM/4.0.0"

#
# Various base helper routines
#

def getKeycloakGitRepositoryRoot():
    """
    Return the absolute path to the Keycloak git repository clone.
    """
    return check_output(['git', 'rev-parse', '--show-toplevel']).decode('utf-8').rstrip()

def isWellFormedWildflyTag(tag):
    """
    Well formed Wildfly & Wildfly Core tag seems to follow the patterns:
    1) First a digit followed by a dot both of them exactly three times.
    2) Followed:
        a) Either by a "Final" suffix, e.g.: "20.0.0.Final",
        b) Or by one of "Alpha", "Beta", "CR" suffices, followed by one digit

    Verifies the tag provided as routine argument follows this schema.

    Exits with error if not.
    """
    if tag and not re.search(r'(\d\.){3}((Alpha|Beta|CR)\d|Final)', tag):
        logging.error("Invalid Wildfly tag: \"%s\", exiting!" % tag)
        sys.exit(1)
    else:
        return tag

def saveUrlToNamedTemporaryFile(baseurl, tag):
    """
    Fetch URL specified as routine argument to named temporary file and
    return the name of that file.

    Otherwise, log an error and exit with failure if HTTP error occurred.
    """
    try:
        with urlopen(baseurl) as response:
            with NamedTemporaryFile(delete=False) as outfile:
                copyfileobj(response, outfile)
                return outfile.name
    except HTTPError:
        logging.error("Failed to download file for tag: %s. Double-check the tag and retry!" % tag)
        sys.exit(1)

    return None

def _emptyNewLine():
    """
    Print additional new line.
    """
    print()

def _logErrorAndExitIf(errorMessage, condition):
    """
    Log particular error message and exit with error if specified condition was
    met.
    """
    if condition:
        _emptyNewLine()
        logging.error(errorMessage)
        _emptyNewLine()
        sys.exit(1)

#
# Various XML search related helper routines
#

def getElementsByXPath(xmlTree, xPath, nameSpace = { "pom" : "%s" % _pom_ns }):
    """
    Given the XML tree return the list of elements matching the 'xPath' from
    the XML 'nameSpace'. 'nameSpace' is optional argument. If not specified
    defaults to the POM XML namespace.

    Returns empty list if no such element specified by 'xPath' is found.
    """
    return xmlTree.xpath(xPath, namespaces = nameSpace)

def getPomDependencyByArtifactId(xmlTree, artifactIdText):
    """
    Given the XML tree return list of POM dependency elements matching
    'artifactIdText' in the text of the element.

    Returns empty list if no such element with 'artifactIdText' is found.
    """
    return xmlTree.xpath('/pom:project/pom:dependencyManagement/pom:dependencies/pom:dependency/pom:artifactId[text()="%s"]' % artifactIdText, namespaces = { "pom" : "%s" % _pom_ns })

def getPomProperty(xmlTree, propertyText):
    """
    Given the XML tree return list of POM property elements matching
    'propertyText' in the text of the element.

    Returns empty list if no such element with 'propertyText' is found.
    """
    return xmlTree.xpath('/pom:project/pom:properties/pom:%s' % propertyText, namespaces = { "pom" : "%s" % _pom_ns })

def getVersionOfPomDependency(xmlElem, groupIdText, artifactIdText):
    """
    Given the list of XML POM dependency elements, return the value of
    '<version>' subelement if 'groupIdText' and 'artifactIdText' match the
    value of groupId and artifactId subelements in the dependency.

    Otherwise, return None.
    """
    version = None
    for entry in xmlElem:
        dependencyElem = entry.getparent()
        for subelem in list(dependencyElem):
            if subelem.tag == '{%s}groupId' % _pom_ns and subelem.text != groupIdText:
                break
            if subelem.tag == '{%s}artifactId' % _pom_ns and subelem.text != artifactIdText:
                break
            if subelem.tag == '{%s}version' % _pom_ns:
                version = subelem.text
                break

    return version

def getXmlRoot(filename):
    """
    Given the 'filename' return the root element of the XML tree.
    """
    return et.parse(filename).getroot()

#
# Data structures and routines to assist with the updates of
# the main Keycloak pom.xml necessary for Wildfly upgrade
#

# List of artifacts from main Keycloak pom.xml excluded from upgrade even though they would
# be usually applicable for the update. This allows to handle special / corner case like for
# example the ones below:
#
# * The version / release tag of specific artifact, as used by upstream of that artifact is
#   actually higher than the version, currently used in Wildfly / Wildfly Core. But the Python
#   version comparing algorithm used by this script, treats it as a lower one
#   (the cache of ApacheDS artifact below),
# * Explicitly avoid the update of certain artifact due whatever reason
#
# Add new entries to this list by moving them out of the _keycloakToWildflyProperties
# dictionary as necessary
_excludedProperties = [
    # Intentionally avoid Apache DS downgrade from "2.0.0.AM26" to Wildfly's current
    # "2.0.0-M24" version due to recent KEYCLOAK-14162
    "apacheds.version"
]

# List of Keycloak specific properties listed in main Keycloak pom.xml file. These entries:
#
# * Either don't represent an artifact version (e.g. "product.rhsso.version" below),
# * Or represent an artifact version, but aren't used listed in Wildfly's or
#   Wildfly-Core's POMs (the artifact is either not referenced in those POM files at all
#   or explicitly excluded in some of them)
_keycloakSpecificProperties = [
    "product.rhsso.version",
    "product.build-time",
    "eap.version",
    "jboss.as.version",
    "jboss.as.subsystem.test.version",
    "jboss.aesh.version",
    "jackson.databind.version",
    "jackson.annotations.version",
    "resteasy.undertow.version",
    "owasp.html.sanitizer.version",
    "sun.xml.ws.version",
    "jetty92.version",
    "jetty93.version",
    "jetty94.version",
    "ua-parser.version",
    "version.com.openshift.openshift-restclient-java",
    "apacheds.codec.version",
    "google.zxing.version",
    "freemarker.version",
    "jetty9.version",
    "liquibase.version",
    "mysql.version",
    "osgi.version",
    "pax.web.version",
    "postgresql.version",
    "mariadb.version",
    "mssql.version",
    "twitter4j.version",
    "jna.version",
    "greenmail.version",
    "jmeter.version",
    "selenium.version",
    "xml-apis.version",
    "subethasmtp.version",
    "replacer.plugin.version",
    "jboss.as.plugin.version",
    "jmeter.plugin.version",
    "jmeter.analysis.plugin.version",
    "minify.plugin.version",
    "osgi.bundle.plugin.version",
    "nexus.staging.plugin.version",
    "frontend.plugin.version",
    "docker.maven.plugin.version",
    "surefire.memory.Xms",
    "surefire.memory.Xmx",
    "surefire.memory.metaspace",
    "surefire.memory.metaspace.max",
    "surefire.memory.settings",
    "tomcat7.version",
    "tomcat8.version",
    "tomcat9.version",
    "spring-boot15.version",
    "spring-boot21.version",
    "spring-boot22.version",
    "webauthn4j.version",
    "org.apache.kerby.kerby-asn1.version",
]

# Mapping of artifact name as used in the main Keycloak pom.xml file to the name
# of the same artifact listed in Wildfly's or Wildfly-Core's pom.xml file
_keycloakToWildflyProperties = {
    "wildfly.version"                                             : "version",
    "wildfly.build-tools.version"                                 : "version.org.wildfly.build-tools",
    # Skip "eap.version" since Keycloak specific
    "wildfly.core.version"                                        : "version.org.wildfly.core",
    # Skip "jboss.as.version" since Keycloak specific
    # Skip "jboss.as.subsystem.test.version" since Keycloak specific
    # Skip "jboss.aesh.version" since Keycloak specific
    "aesh.version"                                                : "version.org.aesh",
    "apache.httpcomponents.version"                               : "version.org.apache.httpcomponents.httpclient",
    "apache.httpcomponents.httpcore.version"                      : "version.org.apache.httpcomponents.httpcore",
    "apache.mime4j.version"                                       : "version.org.apache.james.apache-mime4j",
    "jboss.dmr.version"                                           : "version.org.jboss.jboss-dmr",
    "bouncycastle.version"                                        : "version.org.bouncycastle",
    "cxf.version"                                                 : "version.org.apache.cxf",
    "cxf.jetty.version"                                           : "version.org.apache.cxf",
    "cxf.jaxrs.version"                                           : "version.org.apache.cxf",
    "cxf.undertow.version"                                        : "version.org.apache.cxf",
    "dom4j.version"                                               : "version.dom4j",
    "h2.version"                                                  : "version.com.h2database",
    "jakarta.persistence.version"                                 : "version.jakarta.persistence",
    "hibernate.core.version"                                      : "version.org.hibernate",
    "hibernate.c3p0.version"                                      : "version.org.hibernate",
    "infinispan.version"                                          : "version.org.infinispan",
    "jackson.version"                                             : "version.com.fasterxml.jackson",
    # Skip "jackson.databind.version" and "jackson.annotations.version" since they are derived from ${jackson.version}" above
    "jakarta.mail.version"                                        : "version.jakarta.mail",
    "jboss.logging.version"                                       : "version.org.jboss.logging.jboss-logging",
    "jboss.logging.tools.version"                                 : "version.org.jboss.logging.jboss-logging-tools",
    "jboss-jaxrs-api_2.1_spec"                                    : "version.org.jboss.spec.javax.ws.jboss-jaxrs-api_2.1_spec",
    "jboss-transaction-api_1.3_spec"                              : "version.org.jboss.spec.javax.transaction.jboss-transaction-api_1.3_spec",
    "jboss.spec.javax.xml.bind.jboss-jaxb-api_2.3_spec.version"   : "version.org.jboss.spec.javax.xml.bind.jboss-jaxb-api_2.3_spec",
    "jboss.spec.javax.servlet.jsp.jboss-jsp-api_2.3_spec.version" : "version.org.jboss.spec.javax.servlet.jsp.jboss-jsp-api_2.3_spec",
    "log4j.version"                                               : "version.log4j",
    "resteasy.version"                                            : "version.org.jboss.resteasy",
    # Skip "resteasy.undertow.version" since it's derived from ${resteasy.version} above
    # Skip "owasp.html.sanitizer.version" since Keycloak specific
    "slf4j-api.version"                                           : "version.org.slf4j",
    "slf4j.version"                                               : "version.org.slf4j",
    "sun.istack.version"                                          : "version.com.sun.istack",
    "sun.xml.bind.version"                                        : "version.sun.jaxb",
    "javax.xml.bind.jaxb.version"                                 : "version.javax.xml.bind.jaxb-api",
    # Skip "sun.xml.ws.version" since Keycloak specific
    "sun.activation.version"                                      : "version.com.sun.activation.jakarta.activation",
    "sun.xml.bind.version"                                        : "version.sun.jaxb",
    "org.glassfish.jaxb.xsom.version"                             : "version.sun.jaxb",
    "undertow.version"                                            : "version.io.undertow",
    "elytron.version"                                             : "version.org.wildfly.security.elytron",
    "elytron.undertow-server.version"                             : "version.org.wildfly.security.elytron-web",
    # Skip "jetty92.version", "jetty93.version", and "jetty94.version" since Keycloak specific
    "woodstox.version"                                            : "version.org.codehaus.woodstox.woodstox-core",
    "xmlsec.version"                                              : "version.org.apache.santuario",
    "glassfish.json.version"                                      : "version.org.glassfish.jakarta.json",
    "wildfly.common.version"                                      : "version.org.wildfly.common",
    # Skip "ua-parser.version" since Keycloak specific
    "picketbox.version"                                           : "version.org.picketbox",
    "google.guava.version"                                        : "version.com.google.guava",
    # Skip "version.com.openshift.openshift-restclient-java" since Keycloak specific
    "commons-lang.version"                                        : "version.commons-lang",
    "commons-lang3.version"                                       : "version.commons-lang3",
    "commons-io.version"                                          : "version.commons-io",
    "apacheds.version"                                            : "version.org.apache.ds",
    # Skip "apacheds.codec.version" since Keycloak specific
    # Skip "google.zxing.version" since Keycloak specific
    # Skip "freemarker.version" since Keycloak specific
    # Skip "jetty9.version" since Keycloak specific
    # Skip "liquibase.version" since Keycloak specific
    # Skip "mysql.version" since Keycloak specific
    # Skip "osgi.version" since Keycloak specific
    # Skip "pax.web.version" since Keycloak specific
    # Skip "postgresql.version" since Keycloak specific
    # Skip "mariadb.version" since Keycloak specific
    # Skip "mssql.version" since Keycloak specific
    "servlet.api.30.version"                                      : "version.org.jboss.spec.javax.xml.soap.jboss-saaj-api_1.4_spec",
    "servlet.api.40.version"                                      : "version.org.jboss.spec.javax.servlet.jboss-servlet-api_4.0_spec",
    # Skip "twitter4j.version" since Keycloak specific
    # Skip "jna.version" since Keycloak specific
    # Skip "greenmail.version" since Keycloak specific
    "hamcrest.version"                                            : "version.org.hamcrest",
    # Skip "jmeter.version" since Keycloak specific
    "junit.version"                                               : "version.junit",
    "picketlink.version"                                          : "version.org.picketlink",
    # Skip "selenium.version" since Keycloak specific
    # Skip "xml-apis.version" since intentionally excluded in Wildfly
    # Skip "subethasmtp.version" since Keycloak specific
    "microprofile-metrics-api.version"                            : "version.org.eclipse.microprofile.metrics.api",
    # Skip "replacer.plugin.version" since Keycloak specific
    # Skip "jboss.as.plugin.version" since Keycloak specific
    # Skip "jmeter.plugin.version" since Keycloak specific
    # Skip "jmeter.analysis.plugin.version" since Keycloak specific
    # Skip "minify.plugin.version" since Keycloak specific
    # Skip "osgi.bundle.plugin.version" since Keycloak specific
    "wildfly.plugin.version"                                      : "version.org.wildfly.maven.plugins",
    # Skip "nexus.staging.plugin.version" since Keycloak specific
    # Skip "frontend.plugin.version" since Keycloak specific
    # Skip "docker.maven.plugin.version" since Keycloak specific
    # Skip "tomcat7.version", "tomcat8.version", and "tomcat9.version" since Keycloak specific
    # Skip "spring-boot15.version", "spring-boot21.version", and "spring-boot22.version" since Keycloak specific
    # Skip "webauthn4j.version" since Keycloak specific
    # Skip "org.apache.kerby.kerby-asn1.version" since Keycloak specific
}

def _scanMainKeycloakPomFileForUnknownArtifacts():
    """
    Verify each artifact listed as property in the main Keycloak pom.xml file is present one of the:

    * _excludedProperties list -- explicitly requesting the update to be skipped due some reason,
    * _keycloakSpecificProperties list -- artifact is Keycloak specific,
    * _keycloakToWildflyProperties dictionary -- there's a clear mapping of Keycloak
      artifact property name to corresponding artifact property name as used in Wildfly /
      Wildfly Core

    Logs error message and exits with error if action for a particular artifact is unknown.
    """
    # Absolute path to main Keycloak pom.xml within the repo
    mainKeycloakPomPath = getKeycloakGitRepositoryRoot() + "/pom.xml"

    unknownArtifactMessage = (
            "Found so far unknown '%s' artifact in the main Keycloak pom.xml file!\n"
            "There's no clearly defined action on how to process this artifact yet!\n"
            "It's not an excluded one, not listed as Keycloak specific one, and not\n"
            "present in the set of those to be processed. Add it to one of:\n\n"
            " * _excludedProperties,\n"
            " * _keycloakSpecificProperties,\n"
            " * or _keycloakToWildflyProperties \n\n"
            "data structures in \"wildfly/upgrade/__init__.py\" to dismiss this error!\n"
            "Rerun the script once done."
    )
    for xmlTag in getElementsByXPath(getXmlRoot(mainKeycloakPomPath), "//pom:project/pom:properties/pom:*"):
        artifactName = xmlTag.tag.replace("{%s}" % _pom_ns, "")
        _logErrorAndExitIf (
            unknownArtifactMessage % artifactName,
            artifactName not in itertools.chain(_excludedProperties, _keycloakSpecificProperties, _keycloakToWildflyProperties.keys())
        )

# Empirical list of artifacts to retrieve from Wildfly-Core's pom.xml rather than from Wildfly's pom.xml
_wildflyCoreProperties = [
    "wildfly.build-tools.version",
    "aesh.version",
    "apache.httpcomponents.version",
    "apache.httpcomponents.httpcore.version",
    "jboss.dmr.version",
    "jboss.logging.version",
    "jboss.logging.tools.version",
    "log4j.version",
    "slf4j-api.version",
    "slf4j.version",
    "javax.xml.bind.jaxb.version",
    "undertow.version",
    "elytron.version",
    "elytron.undertow-server.version",
    "woodstox.version",
    "glassfish.json.version",
    "picketbox.version",
    "commons-lang.version",
    "commons-io.version",
    "junit.version",
]

def updateMainKeycloakPomFile(wildflyPomFile, wildflyCorePomFile):
    """
    Synchronize the versions of artifacts listed as properties in the main
    Keycloak pom.xml file with their counterparts taken from 'wildflyPomFile'
    and 'wildflyCorePomFile'.
    """
    wildflyXmlTreeRoot = getXmlRoot(wildflyPomFile)
    wildflyCoreXmlTreeRoot = getXmlRoot(wildflyCorePomFile)

    # Absolute path to main Keycloak pom.xml within the repo
    mainKeycloakPomPath = getKeycloakGitRepositoryRoot() + "/pom.xml"
    keycloakXmlTreeRoot = getXmlRoot(mainKeycloakPomPath)

    _scanMainKeycloakPomFileForUnknownArtifacts()

    for keycloakElemName, wildflyElemName in _keycloakToWildflyProperties.items():

        if keycloakElemName == "wildfly.version":
            wildflyElem = getElementsByXPath(wildflyXmlTreeRoot, '/pom:project/pom:version')
        # Artifact is one of those listed above to be fetched from Wildfly Core's pom.xml
        elif keycloakElemName in _wildflyCoreProperties:
            wildflyElem = getPomProperty(wildflyCoreXmlTreeRoot, wildflyElemName)
        # Otherwise fetch artifact version from Wildfly's pom.xml
        else:
            wildflyElem = getPomProperty(wildflyXmlTreeRoot, wildflyElemName)

        if wildflyElem:
            keycloakElem = getPomProperty(keycloakXmlTreeRoot, keycloakElemName)
            if keycloakElem:
                if keycloakElemName in _excludedProperties:
                    logging.warning(
                        "Not updating version of %s from %s to %s because the artifact is excluded!" %
                        (keycloakElemName, keycloakElem[0].text, wildflyElem[0].text)
                    )
                elif version.parse(wildflyElem[0].text) > version.parse(keycloakElem[0].text):
                    keycloakElem[0].text = wildflyElem[0].text
                else:
                    logging.warning(
                        "Not updating version of %s to %s because existing Keycloak version is either equal or already higher: %s" %
                        (keycloakElemName, wildflyElem[0].text, keycloakElem[0].text)
                    )
        else:
            logging.warning(
                "Unable to locate element with name: %s in %s or %s" %
                (wildflyElemName, wildflyPomFile, wildflyCorePomFile)
            )

    et.ElementTree(keycloakXmlTreeRoot).write(mainKeycloakPomPath, encoding = "UTF-8", pretty_print = True, xml_declaration = True)
    _emptyNewLine()
    logging.info("Wrote updated main Keycloak pom.xml file to: %s" % mainKeycloakPomPath)

# Increment the jboss-parent version both in boms/pom.xml file and in the main Keycloak pom.xml file
def incrementJBossParentVersion():

    BOMS_POM_PATH = REPOSITORY_ROOT + "/boms/pom.xml"
    JBOSS_PARENT_VERSION_ELEM_XPATH = '/pom:project/pom:parent/pom:version'
    INCREMENT_INFO_MSG = "Incremented the version of 'jboss-parent' in '%s' file."
    LOCATE_ELEM_ERR_MSG = "Cannot determine the current 'jboss-parent' version from '%s' file!"

    # Absolute path to main Keycloak pom.xml within the repo
    mainKeycloakPomPath = getKeycloakGitRepositoryRoot() + "/pom.xml"

    bomsPomXmlTreeRoot = getXmlRoot(BOMS_POM_PATH)
    keycloakXmlTreeRoot = getXmlRoot(mainKeycloakPomPath)

    currentJBPVersionElem = getElementsByXPath(bomsPomXmlTreeRoot, JBOSS_PARENT_VERSION_ELEM_XPATH)
    _logErrorAndExitIf(LOCATE_ELEM_ERR_MSG % BOMS_POM_PATH, len(currentJBPVersionElem) != 2)

    #if len(currentJBPVersionElem) == 1:
    currentJBossParentVersion = int(currentJBPVersionElem[0].text)
    newJBossParentVersion = str(currentJBossParentVersion + 1)

    # Update the jboss-parent version in boms/pom.xml
    currentJBPVersionElem[0].text = newJBossParentVersion
    et.ElementTree(bomsPomXmlTreeRoot).write(BOMS_POM_PATH, encoding = "UTF-8", pretty_print = True, xml_declaration = True)
    logging.info(INCREMENT_INFO_MSG % BOMS_POM_PATH)
    # Update the jboss-parent version in main Keycloak pom.xml
    keycloakPomJBPVersionElem = getElementsByXPath(keycloakXmlTreeRoot, JBOSS_PARENT_VERSION_ELEM_XPATH)
    if len(keycloakPomJBPVersionElem) == 1:
        keycloakPomJBPVersionElem[0].text = newJBossParentVersion
        et.ElementTree(keycloakXmlTreeRoot).write(mainKeycloakPomPath, encoding = "UTF-8", pretty_print = True, xml_declaration = True)
        logging.info(INCREMENT_INFO_MSG % mainKeycloakPomPath)
    else:
        logging.error(LOCATE_ELEM_ERR_MSG % mainKeycloakPomPath)
        sys.exit(1)

#
# Routines to assist with Keycloak adapter updates necessary for Wildfly
# upgrade
#

def updateAdapterLicenseFile(wildflyPomFile, wildflyCorePomFile, licenseFile):

    _emptyNewLine()
    logging.info("Processing license file: %s" % licenseFile)

    wildflyXmlTreeRoot = getXmlRoot(wildflyPomFile)
    wildflyCoreXmlTreeRoot = getXmlRoot(wildflyCorePomFile)
    licenseFileXmlTreeRoot = getXmlRoot(licenseFile)

    LICENSE_FILE_PARENT_DIR = os.path.dirname(licenseFile)

    for dependency in getElementsByXPath(licenseFileXmlTreeRoot, '/licenseSummary/dependencies/dependency', nameSpace = {}):
        # First reset artifact name, its current and expected version to their default values
        (artifactName, currentArtifactVersion, expectedArtifactVersion) = ('', '', '')

        for element in dependency.iter():
            # Fetch groupId name
            if element.tag == 'groupId':
                groupName = element.text
            # Fetch artifact name
            elif element.tag == 'artifactId':
                artifactName = element.text
                for xmlRoot in [wildflyXmlTreeRoot, wildflyCoreXmlTreeRoot]:
                    dependencyElem = getPomDependencyByArtifactId(xmlRoot, artifactName)
                    if dependencyElem:
                        dependencyVersion = getVersionOfPomDependency(dependencyElem, groupName, artifactName)
                        if dependencyVersion:
                            if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
                                logging.debug("Found '%s, %s' dependency of '%s' version" % (groupName, artifactName, dependencyVersion))
                            # Strip out heading and trailing POM property expansion notation
                            dependencyVersion = re.sub(r'^\${', '', dependencyVersion)
                            dependencyVersion = re.sub(r'}$', '', dependencyVersion)
                            versionPropertyElem = getPomProperty(xmlRoot, dependencyVersion)
                            _logErrorAndExitIf(
                                "Failed unambiguously to determine the expected version of the '%s' artifact, exiting!" % artifactName,
                                len(versionPropertyElem) != 1
                            )
                            expectedArtifactVersion = versionPropertyElem[0].text

            # Update artifact version to the expected one if necessary
            elif element.tag == 'version':
                currentArtifactVersion = element.text
                if artifactName and expectedArtifactVersion:
                    if version.parse(expectedArtifactVersion) > version.parse(currentArtifactVersion):
                        updatingArtifactVersionMessage = (
                            "Updating the version of '%s, %s' artifact in license file from: '%s' to: '%s'" %
                            (groupName, artifactName, currentArtifactVersion, expectedArtifactVersion)
                        )
                        logging.info(updatingArtifactVersionMessage)
                        element.text = expectedArtifactVersion
                        repositoryRoot = getKeycloakGitRepositoryRoot()
                        # Rename existing license text file tracked in this repository to the filename with updated artifact version
                        for root, dirs, files in os.walk(LICENSE_FILE_PARENT_DIR):
                            for filename in files:
                                if re.search(re.escape(artifactName) + r',' + re.escape(currentArtifactVersion), filename):
                                    currentFilename = filename
                                    currentFileName = currentFilename.replace(repositoryRoot, '').rstrip()
                                    newFilename = currentFilename.replace(currentArtifactVersion, expectedArtifactVersion)
                                    #check_call(['git', 'mv', "%s" % os.path.join(root, currentFilename), "%s" % os.join.join(root, newFilename)], cwd = repositoryRoot)

                    else:
                        artifactVersionAlreadyHigherMessage = (
                            "Not updating the version of the '%s, %s' artifact in license file to '%s'"
                            "\n\tbecause the existing Keycloak version is either equal or already higher: '%s'" %
                            (groupName, artifactName, expectedArtifactVersion, currentArtifactVersion)
                        )
                        logging.warning(artifactVersionAlreadyHigherMessage)

            # Update artifact version in license URL to the expected one
            elif element.tag == 'url':
                if version.parse(expectedArtifactVersion) > version.parse(currentArtifactVersion):
                    # Handle special form of version numbers in release URLs used by org.bouncycastle artifacts
                    if artifactName.endswith('jdk15on'):
                        urlNotationOfCurrentBouncyCastleVersion = 'r' + currentArtifactVersion[0] + 'rv' + currentArtifactVersion[-2:]
                        urlNotationOfExpectedBouncyCastleVersion = 'r' + expectedArtifactVersion[0] + 'rv' + expectedArtifactVersion[-2:]
                        element.text = element.text.replace(urlNotationOfCurrentBouncyCastleVersion, urlNotationOfExpectedBouncyCastleVersion)
                    else:
                        element.text = element.text.replace(currentArtifactVersion, expectedArtifactVersion)

    et.ElementTree(licenseFileXmlTreeRoot).write(licenseFile, encoding = "UTF-8", pretty_print = True, xml_declaration = True)
    _emptyNewLine()
    logging.info("Wrote updated license file to: %s" % licenseFile)

