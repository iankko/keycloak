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

package org.keycloak.testsuite.console.authentication;

import org.jboss.arquillian.graphene.page.Page;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.console.AbstractConsoleTest;
/*
import org.keycloak.testsuite.console.page.authentication.policy.otp.OTPPolicy;
import org.keycloak.testsuite.console.page.authentication.policy.otp.OTPPolicyForm.Digits;
import org.keycloak.testsuite.console.page.authentication.policy.otp.OTPPolicyForm.OTPHashAlg;
import org.keycloak.testsuite.console.page.authentication.policy.otp.OTPPolicyForm.OTPType;
*/
import org.keycloak.testsuite.console.page.authentication.policy.webauthn.WebAuthnPolicy;
import org.keycloak.testsuite.console.page.authentication.policy.webauthn.WebAuthnPolicyForm.AttestationConveyancePreference;
import org.keycloak.testsuite.console.page.authentication.policy.webauthn.WebAuthnPolicyForm.AuthenticatorAttachmentModality;
import org.keycloak.testsuite.console.page.authentication.policy.webauthn.WebAuthnPolicyForm.ResidentKeyRequirement;
import org.keycloak.testsuite.console.page.authentication.policy.webauthn.WebAuthnPolicyForm.SignatureAlgorithm;
import org.keycloak.testsuite.console.page.authentication.policy.webauthn.WebAuthnPolicyForm.UserVerificationRequirement;
import org.keycloak.testsuite.util.WaitUtils;

import static org.junit.Assert.*;

/**
 * @author <a href="mailto:jlieskov@redhat.com">Jan Lieskovsky</a>
 */
public class WebAuthnPolicyTest extends AbstractConsoleTest {
    
    @Page
    private WebAuthnPolicy webauthnPolicyPage;
    
    @Before
    public void beforeWebAuthnPolicyTest() {
        webauthnPolicyPage.navigateTo();
        WaitUtils.pause(1000); // wait for the form to fully render
    }
    
    @Test
    public void webAuthnPolicyTest() {
        webauthnPolicyPage.form().setValues("Test relying party entity name",
                                            SignatureAlgorithm.ES256,
                                            "Relying party identifier",
                                            AttestationConveyancePreference.NONE,
                                            AuthenticatorAttachmentModality.PLATFORM,
                                            ResidentKeyRequirement.YES,
                                            UserVerificationRequirement.REQUIRED,
                                            "10",
                                            true,
                                            "String acceptable aaguids");

	System.out.println("Got the following page source:");
	System.out.println(String.format("%s", driver.getPageSource()));
	try {
            System.out.println("Sleeping for 20 minutes.");
            Thread.sleep(120000000);
        } catch (InterruptedException ie) { }



        /* otpPolicyPage.form().setValues(OTPType.COUNTER_BASED, OTPHashAlg.SHA256, Digits.EIGHT, "10", "50");
        assertAlertSuccess();
        
        RealmRepresentation realm = testRealmResource().toRepresentation();
        assertEquals("hotp", realm.getOtpPolicyType());
        assertEquals("HmacSHA256", realm.getOtpPolicyAlgorithm());
        assertEquals(Integer.valueOf(8), realm.getOtpPolicyDigits());
        assertEquals(Integer.valueOf(10), realm.getOtpPolicyLookAheadWindow());
        assertEquals(Integer.valueOf(50), realm.getOtpPolicyInitialCounter());
        
        otpPolicyPage.form().setValues(OTPType.TIME_BASED, OTPHashAlg.SHA512, Digits.EIGHT, "10", "40");
        assertAlertSuccess();
        
        realm = testRealmResource().toRepresentation();
        assertEquals(Integer.valueOf(40), realm.getOtpPolicyPeriod()); */
    }

}
    
/*    @Test
    public void invalidValuesTest() {
        otpPolicyPage.form().setValues(OTPType.TIME_BASED, OTPHashAlg.SHA1, Digits.SIX, "", "30");
        assertAlertDanger();
        otpPolicyPage.navigateTo();// workaround: input.clear() doesn't work when <input type="number" ...
        
        otpPolicyPage.form().setValues(OTPType.TIME_BASED, OTPHashAlg.SHA1, Digits.SIX, " ", "30");
        assertAlertDanger();
        otpPolicyPage.navigateTo();
        
        otpPolicyPage.form().setValues(OTPType.TIME_BASED, OTPHashAlg.SHA1, Digits.SIX, "no number", "30");
        assertAlertDanger();
        otpPolicyPage.navigateTo();
        
        RealmRepresentation realm = testRealmResource().toRepresentation();
        assertEquals(Integer.valueOf(1), realm.getOtpPolicyLookAheadWindow());

        otpPolicyPage.form().setValues(OTPType.TIME_BASED, OTPHashAlg.SHA1, Digits.SIX, "1", "");
        assertAlertDanger();
        otpPolicyPage.navigateTo();
        
        otpPolicyPage.form().setValues(OTPType.TIME_BASED, OTPHashAlg.SHA1, Digits.SIX, "1", " ");
        assertAlertDanger();
        otpPolicyPage.navigateTo();
        
        otpPolicyPage.form().setValues(OTPType.TIME_BASED, OTPHashAlg.SHA1, Digits.SIX, "1", "no number");
        assertAlertDanger();
        otpPolicyPage.navigateTo();
        
        realm = testRealmResource().toRepresentation();
        assertEquals(Integer.valueOf(30), realm.getOtpPolicyPeriod());
        
        otpPolicyPage.form().setValues(OTPType.COUNTER_BASED, OTPHashAlg.SHA1, Digits.SIX, "1", "");
        assertAlertDanger();
        otpPolicyPage.navigateTo();
        
        otpPolicyPage.form().setValues(OTPType.COUNTER_BASED, OTPHashAlg.SHA1, Digits.SIX, "1", " ");
        assertAlertDanger();
        otpPolicyPage.navigateTo();
        
        otpPolicyPage.form().setValues(OTPType.COUNTER_BASED, OTPHashAlg.SHA1, Digits.SIX, "1", "no number");
        assertAlertDanger();
        otpPolicyPage.navigateTo();
        
        realm = testRealmResource().toRepresentation();
        assertEquals(Integer.valueOf(0), realm.getOtpPolicyInitialCounter());
    }
}

*/
