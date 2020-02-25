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

package org.keycloak.testsuite.console.page.authentication.policy.webauthn;

import org.keycloak.testsuite.page.Form;

import org.keycloak.testsuite.util.UIUtils;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.openqa.selenium.support.ui.Select;

import static org.keycloak.testsuite.util.WaitUtils.waitForPageToLoad;
import static org.keycloak.testsuite.util.WaitUtils.waitUntilElement;

/**
 * @author <a href="mailto:jlieskov@redhat.com">Jan Lieskovsky</a>
 */
public class WebAuthnPolicyForm extends Form {

    @FindBy(id = "name")
    private WebElement relyingPartyEntityName;

    @FindBy(id = "sigalg")
    private Select signatureAlgorithms;

    @FindBy(id = "rpid")
    private WebElement relyingPartyIdentifier;

    @FindBy(id = "attpref")
    private Select attestationConveyancePreference;

    @FindBy(id = "authnatt")
    private Select authenticatorAttachment;

    @FindBy(id = "reqresident")
    private Select residentKeyRequirement;

    @FindBy(id = "usrverify")
    private Select userVerificationRequirement;

    @FindBy(id = "timeout")
    private WebElement timeout;

    @FindBy(id = "avoidsame")
    private WebElement avoidSameAuthenticatorRegistration;

    @FindBy(id = "type")
    private WebElement acceptableAAGUIDs;

    public enum SignatureAlgorithm {

        ES256("ES256"),
        ES384("ES384"),
        ES512("ES512"),
        RS256("RS256"),
        RS384("RS384"),
        RS512("RS512"),
        RS1("RS1");

        private final String name;

        private SignatureAlgorithm(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }

    public enum AttestationConveyancePreference {

        NONE("none"),
        INDIRECT("indirect"),
        DIRECT("direct");

        private final String name;

        private AttestationConveyancePreference(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }

    public enum AuthenticatorAttachmentModality {

        PLATFORM("platform"),
        CROSSPLATFORM("cross-platform");

        private final String name;

        private AuthenticatorAttachmentModality(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }

    public enum ResidentKeyRequirement {

        YES("Yes"),
        NO("No");

        private final String name;

        private ResidentKeyRequirement(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }

    public enum UserVerificationRequirement {

        REQUIRED("required"),
        PREFERRED("preferred"),
        DISCOURAGED("discouraged");

        private final String name;

        private UserVerificationRequirement(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }

    public void setValues(String rpEntityName,
                          SignatureAlgorithm algorithm,
                          String rpIdentifier,
                          AttestationConveyancePreference acPreference,
                          AuthenticatorAttachmentModality aaModality,
                          ResidentKeyRequirement keyRequirement,
                          UserVerificationRequirement verifyUserRequirement,
                          String timeout,
                          boolean avoidSameAuthenticatorRegistration,
                          String acceptableAAGUIDs) {

        UIUtils.setTextInputValue(this.relyingPartyEntityName, rpEntityName);
        this.signatureAlgorithms.selectByValue(algorithm.getName());
        UIUtils.setTextInputValue(this.relyingPartyIdentifier, rpIdentifier);
        this.attestationConveyancePreference.selectByValue(acPreference.getName());
        this.authenticatorAttachment.selectByValue(aaModality.getName());
        this.residentKeyRequirement.selectByValue(keyRequirement.getName());
        this.userVerificationRequirement.selectByValue(verifyUserRequirement.getName());
        UIUtils.setTextInputValue(this.timeout, timeout);
        UIUtils.setTextInputValue(this.acceptableAAGUIDs, acceptableAAGUIDs);

        save();

    }
}
