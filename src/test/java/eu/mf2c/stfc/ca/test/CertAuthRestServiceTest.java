/**
 Copyright 2018-20 UKRI Science and Technology Facilities Council

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License 
 */
package eu.mf2c.stfc.ca.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;

import javax.security.auth.x500.X500Principal;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import eu.mf2c.stfc.util.CA;
import eu.mf2c.stfc.util.CertUtil;

/**
 * Junit for the eu.{@link mf2c.stfc.rest.CertAuthsRestService <em>CertAuthsRestService</em>} class.
 * The REST service must be running before we can run this test.
 * <p>
 * author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * Created 19 Dec 2018
 */
@Ignore
public class CertAuthRestServiceTest {
	/** Message Logger */
	final protected static Logger logger = LogManager.getLogger(CertAuthRestServiceTest.class);
	/** location of the REST application */
	final private static String ep = "http://localhost:8080/certauths/rest/";
	/** Jersey REST client */
	private static Client client; 
	/** Key factory for processing private key */
	public static java.security.KeyFactory keyFactory;
	/** X.509 certificate factory for processing certificates */
	public static CertificateFactory certFactory;

	/**
	 * {@inheritDoc}
	 * 
	 * @throws Exception
	 *             on error
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		client = ClientBuilder.newClient();
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		keyFactory = KeyFactory.getInstance("RSA", "BC");
		certFactory = CertificateFactory.getInstance("X.509");
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @throws Exception
	 *             on error
	 */
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		client.close();
		client = null;keyFactory = null;
		certFactory = null;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @throws Exception
	 *             on error
	 */
	@Before
	public void setUp() throws Exception {
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @throws Exception
	 *             on error
	 */
	@After
	public void tearDown() throws Exception {
	}
	/**
	 * Test generating a private key and certificate
	 * from the IT2TRUSTEDCA REST resource
	 */
	@Test
	public void testAIT2trusted() {
		System.out.println("\nabout to run testAIT2trusted");
		String cn = "148.69.0.20";
		CA ca = CA.IT2TRUSTEDCA;
		System.out.println("About to invoke endpoint for " + ca.toString() + "....");
		testTrustedCA(cn, ca);		
	}
	/**
	 * Test generating a certificate from the IT2UNTRUSTEDCA REST resource.
	 */
	@Test
	public void testBIT2untrusted() {
		System.out.println("\nabout to run testBIT2untrusted");
		String cn = "148.69.0.20";
		CA ca = CA.IT2UNTRUSTEDCA;			
		System.out.println("About to invoke endpoint for " + ca.toString() + "....");
		testUntrustedCA(cn, ca);
	}
		
	/**
	 * Test input validation of the trustedCA by sending a 
	 * {@link org.bouncycastle.pkcs.PKCS10CertificationRequest <em>PKCS10CertificationRequest</em>}
	 * instead of a common name to the service.  Service should return 400.
	 */
	@Test
	public void testCTrustedCAIncorrectInput() {
		System.out.println("\nabout to run testCTrustedCAIncorrectInput");
		String cn = "148.69.0.20";
		CA ca = CA.UC1TRUSTEDCA;
		KeyPair keypair = CertUtil.genKeyPair();
		String csrString = getCSRString(cn, ca, keypair);
		System.out.println("About to invoke endpoint for " + ca.toString() + "....");
		testTrustedCAException(csrString, ca);		
	}
	/**
	 * Test calling an non-existing CA.  Service should return 404.
	 * <p>
	 * @param cn	{@java.lang.String <em>String</em>} representation of the common name
	 * @param ca	The {@link eu.mf2c.stfc.util.CA <em>CA</em>} to test.
	 */
	@Test
	public void testDNonExistingCA() {
		System.out.println("\nabout to run testDNonExistingCA");
		String cn = "148.69.0.20";
		String ca = "AnyOldCA";
		System.out.println("testDNonExistingCA about to call the : " + ca + "....");
		//
		Response response = client.target(ep).path(ca.toString().toLowerCase()).request(MediaType.TEXT_PLAIN).post(Entity.entity(cn, MediaType.TEXT_PLAIN));
		//
		System.out.println("About to check response from : " + ca.toString() + "....");
		String responseStr = response.readEntity(String.class);
		if(response.getStatus() != 404) {
			//
			logger.error("RC should be 404! But got: " + responseStr);
			fail("RC should be 404! But got: " + responseStr);
		}
	}
	/**
	 * Test input validation of the untrustedCA by sending a common name instead of an
	 * {@link org.bouncycastle.pkcs.PKCS10CertificationRequest <em>PKCS10CertificationRequest</em>}
	 * to the service.  Service should return 400.
	 */
	@Test
	public void testEUntrustedCAIncorrectInput() {
		System.out.println("\nabout to run testEUntrustedCAIncorrectInput");
		String cn = "148.69.0.20";
		CA ca = CA.UC1UNTRUSTEDCA;
		System.out.println("About to call the : " + ca.toString() + "....");
		//
		Response response = client.target(ep).path(ca.toString().toLowerCase()).request(MediaType.TEXT_PLAIN).post(Entity.entity(cn, MediaType.TEXT_PLAIN));
		//
		System.out.println("About to check response from : " + ca.toString() + "....");
		String responseStr = response.readEntity(String.class);
		if(response.getStatus() != 400) {
			//
			logger.error("RC should be 400! But got: " + responseStr);
			fail("RC should be 400! But got: " + responseStr);
		}
		
		
	}
	////////////////////////////////private methods////////////////
	
	/**
	 * Core method for testing a trusted CA REST endpoint.
	 * <p>
	 * @param cn	{@java.lang.String <em>String</em>} representation of the common name
	 * @param ca	The {@link eu.mf2c.stfc.util.CA <em>CA</em>} to test. 
	 */
	private void testTrustedCA(String cn, CA ca) {
		//add resource path segment
		Response response = client.target(ep).path(ca.toString().toLowerCase()).request(MediaType.TEXT_PLAIN).post(Entity.entity(cn, MediaType.TEXT_PLAIN));
		//
		String responseStr = response.readEntity(String.class);
		if(response.getStatus() == 200) {
			//
			try {
				System.out.println("The responseStr: \n" + responseStr);
				verifyCertificate(responseStr, ca, cn );
			} catch (Exception e) {
				logger.error("Failed to verify the credentials from it2trustedca! Exception msg: " + e.getMessage());
				fail("Failed to verify the credentials from it2trustedca! Exception msg: " + e.getMessage());
			}			
		}else {
			logger.error("Failed to generate the credentials from it2trustedca! Status code is: " + response.getStatus() + ":" + responseStr);
			fail("Failed to generate the credentials from it2trustedca! Status code is: " + response.getStatus() + ":" + responseStr);
		}		
	}
	/**
	 * Core method for testing an untrusted CA REST endpoint.  The method 
	 * generates the required {@link org.bouncycastle.pkcs.PKCS10CertificationRequest
	 *            <em>PKCS10CertificationRequest</em>}
	 * <p>
	 * @param cn	{@java.lang.String <em>String</em>} representation of the common name
	 * @param ca	The {@link eu.mf2c.stfc.util.CA <em>CA</em>} to test.
	 */
	private void testUntrustedCA(String cn, CA ca) {
		//
		KeyPair keypair = CertUtil.genKeyPair();
		String csrString = getCSRString(cn, ca, keypair);
		/*PKCS10CertificationRequest csr = null;
		// 
		String ou = ca.toString().substring(0, 3) + "-UntrustedCA";
		System.out.println("ou: " + ou);
		PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
				new X500Principal("CN=" + cn + ", OU=" + ou + ", O=mF2C, C=EU "), keypair.getPublic());
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		ContentSigner signer;
		String csrString = null;
		try {
			signer = csBuilder.build(keypair.getPrivate());
			csr = p10Builder.build(signer);
			csrString = CertUtil.getCSRString(csr);
		}catch(Exception e) {
			fail("Error generating the CSR for testing " + ca.toString());
		}*/
		if(csrString == null) {
			fail("Failed to generate CSR String with cn(" + cn + ") for " + ca.toString());
			return;
		}
		System.out.println("About to call the : " + ca.toString() + "....");
		//
		Response response = client.target(ep).path(ca.toString().toLowerCase()).request(MediaType.TEXT_PLAIN).post(Entity.entity(csrString, MediaType.TEXT_PLAIN));
		//
		System.out.println("About to check response from : " + ca.toString() + "....");
		String responseStr = response.readEntity(String.class);
		if(response.getStatus() == 200) {
			//
			try {
				System.out.println("The responseStr: \n" + responseStr);
				X509Certificate cert = getCertFromStr(responseStr);
				//System.out.println("Same key? : " + certificate.getPublicKey().equals(keypair.getPublic()));
				assertTrue("The public keys do not match!", cert.getPublicKey().equals(keypair.getPublic()));
				verifyCertificateContent(cert, ca, cn);
			} catch (Exception e) {
				logger.error("Failed to verify the credentials from it2trustedca! Exception msg: " + e.getMessage());
				fail("Failed to verify the credentials from it2trustedca! Exception msg: " + e.getMessage());
			}			
		}else {
			logger.error("Failed to generate the credentials from it2trustedca! Status code is: " + response.getStatus() + ":" + responseStr);
			fail("Failed to generate the credentials from it2trustedca! Status code is: " + response.getStatus() + ":" + responseStr);
		}
	}
	/**
	 * Test incorrect content sent to the trusted CA.  Service should return 400.
	 * <p>
	 * @param csrString		a String representation of an {@link org.bouncycastle.pkcs.PKCS10CertificationRequest
	 *            <em>PKCS10CertificationRequest</em>}
	 * @param ca	The {@link eu.mf2c.stfc.util.CA <em>CA</em>} to test.
	 */
	private void testTrustedCAException(String csrString, CA ca) {
		System.out.println("about to call the : " + ca.toString() + "....");
		//
		Response response = client.target(ep).path(ca.toString().toLowerCase()).request(MediaType.TEXT_PLAIN).post(Entity.entity(csrString, MediaType.TEXT_PLAIN));
		//
		System.out.println("About to check response from : " + ca.toString() + "....");
		String responseStr = response.readEntity(String.class);
		if(response.getStatus() != 400) {
			//
			logger.error("RC should be 400! But got: " + responseStr);
			fail("RC should be 400! But got: " + responseStr);
		}
	}

	/**
	 * Create an X509 certificate object from a String representation.
	 * 
	 * @param certString
	 *            the String representation
	 * @return the generated certificate
	 * @throws CertificateException
	 *             on error generating the certificate
	 * @throws IOException
	 *             if error reading String
	 */
	private X509Certificate getCertFromStr(String certString) throws CertificateException, IOException {
		//
		PemReader pemReader = new PemReader(new StringReader(certString));
		byte[] requestBytes = pemReader.readPemObject().getContent();
		pemReader.close();
		ByteArrayInputStream in = new ByteArrayInputStream(requestBytes);
		return (X509Certificate) certFactory.generateCertificate(in);
	}

	/**
	 * Create a private key object in PKCS8 format from a String representation
	 * <p>
	 * 
	 * @param keyString
	 *            the String representation
	 * @return the created private key object
	 * @throws NoSuchAlgorithmException
	 *             if key is encrypted with an unsupported algorithm
	 * @throws NoSuchProviderException
	 *             if no security provider is provided
	 * @throws InvalidKeySpecException
	 *             if key is invalid
	 * @throws IOException
	 *             if error reading String
	 */
	private PrivateKey getKeyFromStr(String keyString)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {

		org.bouncycastle.util.io.pem.PemReader pemReader = new PemReader(new StringReader(keyString));
		PemObject pemObject = pemReader.readPemObject();
		byte[] content = pemObject.getContent();
		pemReader.close();
		//
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
		// java.security.KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
		System.out.println("About to generate private key from spec....");
		return keyFactory.generatePrivate(privKeySpec);

	}
	/**
	 * Check the provided {@link java.security.X509Certificate <em>X509Certificate</em>} objects against the provided parameters.
	 * <p>
	 * @param privKey		the {@link java.security.PrivateKey <em>PrivateKey</em>} associated with the certificate object
	 * @param certificate	the {@link java.security.X509Certificate <em>X509Certificate</em>} to check
	 * @param targetCA		issuing {@link eu.mf2c.stfc.util.CA <em>CA</em}
	 * @param cn			the common name of the {@link java.security.X509Certificate <em>X509Certificate</em>}
	 * @throws InvalidKeySpecException	if error creating a reciprocal public key from the provided  
	 * @throws IOException	if error reading String representation of the credential object 
	 * @throws NoSuchProviderException	if no security provider is provided 
	 * @throws NoSuchAlgorithmException	if key is encrypted with an unsupported algorithm
	 * @throws CertificateException	on error generating the certificate
	 */
	private void verifyCertificate(String cert, CA targetCA, String cn)
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException {
		//I have already checked the Issuer's public key against the private key used to sign the certificate during the generation process
		//
		String pkString = cert.substring(0, cert.indexOf("-----BEGIN CERTIFICATE"));
		String certString = cert.substring(cert.indexOf("-----BEGIN CERTIFICATE"));
		// System.out.println("private key String : " + pkString);
		// System.out.println("cert String : " + certString);
		// loads the credential and check
		PrivateKey privKey = getKeyFromStr(pkString);
		// System.out.println("about to get certficiate from String ...");
		X509Certificate certificate = getCertFromStr(certString);
		// System.out.println("about to verify key...");		// verify key
		RSAPrivateCrtKey priv = (RSAPrivateCrtKey) privKey;
		RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent());
		PublicKey pubKey = keyFactory.generatePublic(rsaSpec);
		assertEquals("The public keys do not match!", pubKey, certificate.getPublicKey());		
		//
		verifyCertificateContent(certificate, targetCA, cn);	
	}
	
	
	/**
	 * Core method to spot check contents of the {@link java.security.X509Certificate <em>X509Certificate</em>}
	 * <p>
	 * @param certificate	the {@link java.security.X509Certificate <em>X509Certificate</em>} to check
	 * @param targetCA	issuing {@link eu.mf2c.stfc.util.CA <em>CA</em}
	 * @param cn		the common name of the {@link java.security.X509Certificate <em>X509Certificate</em>}
	 * @throws CertificateParsingException	if error getting the extended key usages
	 */
	private void verifyCertificateContent(X509Certificate certificate, CA targetCA, String cn) throws CertificateParsingException {
		//
		Principal issuer = certificate.getIssuerDN();
		String target = targetCA.toString().substring(0, 3) + "-" + targetCA.toString().substring(3);
		System.out.println("target : " + target.toLowerCase());
		assertTrue("Incorrect issuer name : " + issuer.getName(),
				issuer.getName().toLowerCase().contains(target.toLowerCase()));
		Principal subject = certificate.getSubjectDN();
		assertTrue("Incorrect subject name : " + subject.getName(), subject.getName().contains(cn));
		// check keyusage
		boolean[] ku = certificate.getKeyUsage();
		if (ku != null) {
			assertTrue("should have digitalSignature key usage!", ku[0] == true);
			assertTrue("should not have nonRepudiation key usage!", ku[1] == false);
			assertTrue("should have keyEncipherment key usage!", ku[2] == true);
			assertTrue("should have dataEncipherment key usage!", ku[3] == true);
			assertTrue("should not have keyAgreement key usage!", ku[4] == false);
			assertTrue("should not have keyCertSign key usage!", ku[5] == false);
			assertTrue("should not have cRLSign key usage!", ku[6] == false);
			assertTrue("should not have encipherOnly key usage!", ku[7] == false);
			assertTrue("should not have decipherOnly key usage!", ku[8] == false);
		} else {
			fail("key usage is null!");
		}
		// check extended key usage
		List<String> extendedKU = certificate.getExtendedKeyUsage();
		if (extendedKU == null || extendedKU.isEmpty()) {
			fail("no extended key usages!");
		} else {
			assertTrue("Should have client auth extended key usage",
					extendedKU.contains(KeyPurposeId.id_kp_clientAuth.toString()));
			assertTrue("Should have server auth extended key usage",
					extendedKU.contains(KeyPurposeId.id_kp_serverAuth.toString()));
			// can't be bother to check the rest :)
		}
		// check basic constraint
		int bcInt = certificate.getBasicConstraints();
		// System.out.print("bcInt : " + bcInt); // is -1
		assertTrue("an end-entity certificate should only have -1 cert path length constraint!", bcInt == -1);
	}
	/**
	 * Generate a String representation of an {@link org.bouncycastle.pkcs.PKCS10CertificationRequest
	 *            <em>PKCS10CertificationRequest</em>}
	 * @param cn	{@java.lang.String <em>String</em>} representation of the common name
	 * @param ca	The {@link eu.mf2c.stfc.util.CA <em>CA</em>} to test.
	 * @param keypair The {@link java.security.KeyPair <em>KeyPair</em>} associated with the
	 * 				{@link org.bouncycastle.pkcs.PKCS10CertificationRequest <em>PKCS10CertificationRequest</em>}
	 * @return		The generated String or null.
	 */
	private String getCSRString(String cn, CA ca, KeyPair keypair) {
		PKCS10CertificationRequest csr = null;
		// 
		String ou = ca.toString().substring(0, 3) + "-UntrustedCA";
		System.out.println("ou: " + ou);
		PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
				new X500Principal("CN=" + cn + ", OU=" + ou + ", O=mF2C, C=EU "), keypair.getPublic());
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		ContentSigner signer;
		String csrString = null;
		try {
			signer = csBuilder.build(keypair.getPrivate());
			csr = p10Builder.build(signer);
			csrString = CertUtil.getCSRString(csr);
		}catch(Exception e) {
			fail("Error generating the CSR for testing " + ca.toString());
		}
		return csrString;
	}
	


}
