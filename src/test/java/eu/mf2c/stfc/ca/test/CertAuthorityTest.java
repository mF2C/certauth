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
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
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
//import org.junit.FixMethodOrder;
//import org.junit.runners.MethodSorters;

import org.junit.Test;

import eu.mf2c.stfc.ca.CertAuthority;
import eu.mf2c.stfc.util.CA;
import eu.mf2c.stfc.util.CertUtil;

/**
 * JUnit tests of {@link eu.mf2c.stfc.ca.CertAuthority <em>CertAuthority</em>}
 * class.
 * <p>
 * 
 * author Shirley Crompton
 * email shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group, UKRI Science and Technology Council
 * Created 17 Dec 2018
 */
//@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CertAuthorityTest {

	/** Message Logger */
	final protected static Logger logger = LogManager.getLogger(CertAuthorityTest.class);
	/** The Class being tested */
	private static CertAuthority ca;
	/** Key factory for processing private key */
	private static java.security.KeyFactory keyFactory;
	/** X.509 certificate factory for processing certificates */
	private static CertificateFactory certFactory;
	/** Secure random number generator attribute */
	private static SecureRandom random;

	/**
	 * {@inheritDoc}
	 * 
	 * @throws Exception
	 *             on error
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		ca = new CertAuthority();
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		keyFactory = KeyFactory.getInstance("RSA", "BC");
		certFactory = CertificateFactory.getInstance("X.509");
		random = new SecureRandom();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @throws Exception
	 *             on error
	 */
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		ca = null;
		keyFactory = null;
		certFactory = null;
		random = null;
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
	 * Wrapper for testing the generation of a trust certificate for IT2.
	 */
	@Test
	public void testGenTrustedCertA() {
		this.testGenTrustedCert("148.19.0.19", CA.IT2TRUSTEDCA);
	}
	/**
	 * Wrapper for testing the generation of a trust certificate for UC1.
	 */
	@Test
	public void testGenTrustedCertB() {
		this.testGenTrustedCert("148.20.0.20", CA.UC1TRUSTEDCA);
	}
	/**
	 * Wrapper for testing the generation of a trust certificate for UC2.
	 */
	@Test
	public void testGenTrustedCertC() {
		this.testGenTrustedCert("148.21.0.21", CA.UC2TRUSTEDCA);
	}
	/**
	 * Wrapper for testing the generation of a trust certificate for UC3.
	 */
	@Test
	public void testGenTrustedCertD() {
		this.testGenTrustedCert("148.22.0.22", CA.UC3TRUSTEDCA);
	}
	/**
	 * Wrapper for testing the generation of an untrust certificate for IT2.
	 * This uses a {@link org.bouncycastle.pkcs.PKCS10CertificationRequest <em>PKCS10CertificationRequest</em>} object.
	 */
	@Test
	public void testGenUnTrustedCertA() {
		this.testGenUntrustedCert("148.23.0.23", CA.IT2UNTRUSTEDCA);
	}
	/**
	 * Wrapper for testing the generation of an untrust certificate for UC1.
	 * This uses a {@link org.bouncycastle.pkcs.PKCS10CertificationRequest <em>PKCS10CertificationRequest</em>} object.
	 */
	@Test
	public void testGenUnTrustedCertB() {
		this.testGenUntrustedCert("148.24.0.24", CA.UC1UNTRUSTEDCA);
	}
	/**
	 * Wrapper for testing the generation of an untrust certificate for UC2.
	 * This uses a {@link org.bouncycastle.pkcs.PKCS10CertificationRequest <em>PKCS10CertificationRequest</em>} object.
	 */
	@Test
	public void testGenUnTrustedCertC() {
		this.testGenUntrustedCert("148.25.0.25", CA.UC2UNTRUSTEDCA);
	}
	/**
	 * Wrapper for testing the generation of an untrust certificate for UC3.
	 * This uses a {@link org.bouncycastle.pkcs.PKCS10CertificationRequest <em>PKCS10CertificationRequest</em>} object.
	 */
	@Test
	public void testGenUnTrustedCertD() {
		this.testGenUntrustedCert("148.26.0.26", CA.UC3UNTRUSTEDCA);
	}
	/////////////////////////// PRIVATE METHODS///////////////////////////
	/**
	 * Core method for getting a trusted certificate
	 * <p>
	 * @param cn	the common name 
	 * @param targetCA	
	 */
	private void testGenTrustedCert(String cn, CA targetCA) {
		System.out.println("\nTestGenTrustedCert for " + targetCA.toString() + ":\n");

		try {
			String cert = ca.generateTrustCert(cn, targetCA);
			// verify the contents
			verifyCertificate(cert, targetCA, cn);
		} catch (Exception e) {
			logger.error("Failed to generate trusted certificate with cn(" + cn + ") from ca(" + targetCA.toString()
					+ "): " + e.getMessage());
			fail("Failed to generate a correct trusted certificate with cn(" + cn + ") from ca(" + targetCA.toString() + "): "
					+ e.getMessage());
		}

	}
	/**
	 * Core method for getting an untrusted certificate using a 
	 * {@link org.bouncycastle.pkcs.PKCS10CertificationRequest <em>PKCS10CertificationRequest</em>} object.
	 * <p>
	 * @param cn	{@link java.lang.String <em>String</em>} representation of the common name
	 * @param targetCA	the issuing {@link eu.mf2c.stfc.util.CA <em>CA</em>}
	 */
	private void testGenUntrustedCert(String cn, CA targetCA) {
		System.out.println("\nTestGenUntrustedCert for " + targetCA.toString() + ":\n");
		//get a keypair
		try {
			KeyPair keypair = genKeyPair();
			PKCS10CertificationRequest csr = null;
			// keypair generated by the PMCertManager //UNTRUSTEDCA
			String ou = targetCA.toString().substring(0, 3) + "-UntrustedCA";
			System.out.println("ou: " + ou);
			PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
					new X500Principal("CN=" + cn + ", OU=" + ou + ", O=mF2C, C=EU "), keypair.getPublic());
			JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
			ContentSigner signer;
			signer = csBuilder.build(keypair.getPrivate());
			csr = p10Builder.build(signer);
			X509Certificate certificate = CertUtil.signCSR(csr, targetCA);
			//
			//System.out.println("Same key? : " + certificate.getPublicKey().equals(keypair.getPublic()));
			assertTrue("The public keys do not match!", certificate.getPublicKey().equals(keypair.getPublic()));			//
			verifyCertificateContent(certificate, targetCA, cn);	
			//
		}catch(Exception e) {
			logger.error("Failed to generate a correct unstrusted certificate using CSR for cn(" + cn + ") from ca(" + targetCA.toString() + "): " + 
					 e.getMessage());
			fail("Failed to generate a correct unstrusted certificate using CSR for cn(" + cn + ") from ca(" + targetCA.toString() + "): " + 
					 e.getMessage());
		}
		
	}
	/**
	 * Generate an RSA {@link java.security.KeyPair <em>KeyPair</em>} of 2048 length
	 * <p>
	 * @return	the generated {@link java.security.KeyPair <em>KeyPair</em>}
	 * @throws NoSuchAlgorithmException	if RSA is not supported
	 */
	private KeyPair genKeyPair() throws NoSuchAlgorithmException {

		KeyPairGenerator keyGen;
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048, random);
			return keyGen.generateKeyPair();			
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
	 * @param cert	the {@link java.security.X509Certificate <em>X509Certificate</em>} to check
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
	
}
