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
package eu.mf2c.stfc.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneOffset;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Miscellaneous utilities for working with X.509 certificates.
 * <p>
 * 
 * author Shirley Crompton
 * email shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group, UKRI Science and Technology Council
 * Created 11 Dec 2018
 */
public class CertUtil {
	/** Message Logger */
	final static Logger logger = LogManager.getLogger(CertUtil.class);
	/** Secure random number generator attribute */
	private static SecureRandom random = new SecureRandom();

	/**
	 * Helper method to load an X.509 certificate from file. The certificate needs
	 * to be in PEM format.
	 * <p>
	 * 
	 * @param fileName
	 *            {@link java.lang.String <em>String</em>} representation of the
	 *            file name
	 * @return the generated {@link java.security.cert.X509Certificate
	 *         <em>X509Certificate</em>} or null.
	 */
	public static X509Certificate loadCert(String fileName) {

		// add the target folder and create an absolute path
		String absPath = File.separator + "var" + File.separator + "lib" + File.separator + "certauths" + File.separator
				+ fileName;
		//
		X509Certificate cert = null;
		try (FileInputStream inStream = new FileInputStream(new File(absPath))) {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			//
			cert = (X509Certificate) cf.generateCertificate(inStream);
		} catch (CertificateException e) {
			System.out.println("Certificate Exception loading CA cert: " + e.getMessage() + "from " + absPath);
			logger.error("Exception loading cert: " + e.getMessage() + "from " + absPath);
		} catch (IOException e) {
			System.out.println("IO Exception loading cert: " + e.getMessage() + "from " + absPath);
			logger.error("IO Exception loading cert: " + e.getMessage() + "from " + absPath);
		}
		return cert;
	}

	/**
	 * Load a {@link java.security.PrivateKey <em>PrivateKey</em>} from a PEM file.
	 * <p>
	 * 
	 * @param fileName
	 *            {@link java.lang.String <em>String</em>} representation of the
	 *            file name
	 * @return the generated {@link java.security.PrivateKey <em>PrivateKey</em>} or
	 *         null.
	 */
	public static PrivateKey loadPrivateKey(String fileName) {
		// add the target folder and create an absolute path
		String absPath = File.separator + "var" + File.separator + "lib" + File.separator + "certauths" + File.separator
				+ fileName;
		// http://www.xinotes.net/notes/note/1899/
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		PemReader pemReader = null;
		PrivateKey key = null;
		FileInputStream inStream = null;
		try {
			// openSSL generates the private key in base64 encoded format, so is PEM
			inStream = new FileInputStream(new File(absPath));
			pemReader = new PemReader(new InputStreamReader(inStream));
			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
			java.security.KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
			key = factory.generatePrivate(privKeySpec);
			System.out.println("loaded ca private key in " + key.getFormat() + " format.");
			logger.debug("loaded ca private key in " + key.getFormat() + " format.");
		} catch (FileNotFoundException e) {
			System.out.println(("FileNotFoundException loading private key from " + absPath + " : " + e.getMessage()));
			logger.error("FileNotFoundException loading private key from " + absPath + " : " + e.getMessage());
		} catch (IOException e) {
			System.out.println(("IOException loading private key from " + absPath + " : " + e.getMessage()));
			logger.error("IOException loading private key from " + absPath + " : " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.out
					.println(("NoSuchAlgorithmException loading private key from " + absPath + " : " + e.getMessage()));
			logger.error("NoSuchAlgorithmException loading private key from " + absPath + " : " + e.getMessage());
		} catch (NoSuchProviderException e) {
			System.out
					.println(("NoSuchProviderException loading private key from " + absPath + " : " + e.getMessage()));
			logger.error("NoSuchProviderException loading private key from " + absPath + " : " + e.getMessage());
		} catch (InvalidKeySpecException e) {
			System.out
					.println(("InvalidKeySpecException loading private key from " + absPath + " : " + e.getMessage()));
			logger.error("InvalidKeySpecException loading private key from " + absPath + " : " + e.getMessage());
		} finally {
			try {
				if (pemReader != null) {
					pemReader.close();
				}
				if (inStream != null) {
					inStream.close();
				}
			} catch (IOException ignore) {
				logger.warn("IOException closing stream/s");
			}
		}
		// System.out.println("key: " + key == null ? "null" : key.toString());
		logger.debug("loaded private key from " + absPath);
		return key;
	}
	/**
	 * Generate a {@link org.bouncycastle.pkcs.PKCS10CertificationRequest
	 *            <em>PKCS10CertificationRequest</em>} from a {@link java.lang.String <em>String</em>}
	 *            representation
	 * @param csrString		{@link java.lang.String <em>String</em>} representation
	 * @return	the generated {@link org.bouncycastle.pkcs.PKCS10CertificationRequest
	 *            <em>PKCS10CertificationRequest</em>} object
	 * @throws IOException	if error reading the {@link java.lang.String <em>String</em>} 
	 */
	public static PKCS10CertificationRequest loadCSR(String csrString) throws IOException {
		//
		PemReader pemReader = new PemReader(new StringReader(csrString));
		byte[] requestBytes = pemReader.readPemObject().getContent();
		pemReader.close();
		//
		return new PKCS10CertificationRequest(requestBytes);		
	}
	/**
	 * Write an {@link java.security.cert.X509Certificate <em>X509certificate</em>} to file. 
	 * The output file would be in PEM format.
	 * <p>
	 * 
	 * @param x509Cert
	 *            the {@link java.security.cert.X509Certificate <em>X509certificate</em>} to write
	 * @param fileName
	 *            the target file name
	 * @param ca
	 *            the issuing {@link eu.mf2c.stfc.util.CA <em>CA</em>}
	 * @throws Exception
	 *             on error
	 */
	public static void writeCertPEM2File(X509Certificate x509Cert, String fileName, CA ca) throws Exception {
		// add the target folder and create an absolute path
		String absPath = File.separator + "var" + File.separator + "lib" + File.separator + "certauths" + File.separator
				+ ca.toString() + File.separator + fileName;
		System.out.println("the X509 file target : " + absPath);
		logger.debug("the X509 file target : " + absPath);
		// eg. filename = "resources\\rsa_pub.pem"
		if (x509Cert != null) {
			PemWriter pw = new PemWriter(new OutputStreamWriter(new FileOutputStream(fileName)));
			// the description is used in the PEM file: BEGIN <description> .....
			pw.writeObject(new PemObject("CERTIFICATE", x509Cert.getEncoded()));
			pw.close();

		} else {
			System.out.println("Cannot write X.509 cert to " + fileName);
			logger.error("Cannot write X.509 cert to " + fileName);
		}
	}

	/**
	 * Write a {@link java.security.PrivateKey <em>PrivateKey</em>} out to file, the
	 * key is base64 encoded.
	 * <p>
	 * 
	 * @param privKey
	 *            the {@link java.security.PrivateKey <em>PrivateKey</em>}
	 * @param fileName
	 *            {@link java.lang.String <em>String</em>} representation of the file
	 *            name
	 * @param ca
	 *            the issuing {@link eu.mf2c.stfc.util.CA <em>CA</em>}
	 * @throws Exception
	 *             on error
	 */
	public static void writePrivateKey2File(PrivateKey privKey, String fileName, CA ca) throws Exception {
		// add the target folder and create an absolute path
		String absPath = File.separator + "var" + File.separator + "lib" + File.separator + "certauths" + File.separator
				+ ca.toString() + File.separator + fileName;
		System.out.println("the private key file target : " + absPath);
		logger.debug("the private key file target : " + absPath);
		//
		try (PemWriter pw = new PemWriter(new OutputStreamWriter(new FileOutputStream(fileName)))) {
			// the description is used : BEGIN <description> in the PEM file
			pw.writeObject(new PemObject("RSA PRIVATE KEY", privKey.getEncoded()));
			pw.close();
		} /*
			 * catch (Exception e) { //
			 * System.out.println("Error writing out private key to " + filepath + ": " +
			 * e.getMessage()); logger.error("Error writing out private key to " + filepath
			 * + ": " + e.getMessage()); }
			 */
	}
	/**
	 * Write out the provided credential object&#47;s to a {@link java.lang.String <em>String</em>} object.
	 * The {@link java.security.PrivateKey <em>PrivateKey</em>} object is optional.
	 * <p>
	 * @param privKey	a {@link java.security.PrivateKey <em>PrivateKey</em>} object or null
	 * @param cert		a {@link java.security.cert.X509Certificate <em>X509certificate</em>} object
	 * @return	a {@link java.lang.String <em>String</em>} representation of the credential&#47;s
	 * @throws IOException on error
	 */
	public static String concateCredentials(PrivateKey privKey, X509Certificate cert) throws IOException {
		//
		StringWriter sw = new StringWriter();
		JcaPEMWriter pw = new JcaPEMWriter(sw);
		if(privKey != null) {
			pw.writeObject(privKey);
			pw.flush();			
		}
		pw.writeObject(cert);
		pw.flush();
		pw.close();		
		//
		logger.debug("The credential" + (privKey == null ? "" : "s") + ":\n");
		logger.debug(sw.toString());
		return sw.toString();		
	}

	/**
	 * Generate an RSA {@link java.security.KeyPair <em>KeyPair</em>} of 2048
	 * length.
	 * <p>
	 * *
	 * 
	 * @return the generated {@link java.security.KeyPair <em>KeyPair</em>} or null.
	 */
	public static KeyPair genKeyPair() {
		KeyPair kp = null;
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048, random);
			kp = keyGen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error generating RSA keypair: " + e.getMessage());
			logger.error("Error generating RSA keypair: " + e.getMessage());
		}
		return kp;
	}

	/**
	 * Wrapper method to sign a certification request and issue an end&#45;entity
	 * X.509 Certificate. The following key usages and extended key usages are
	 * set&#58;
	 * <ul>
	 * <li>dataEncipherment</li>
	 * <li>digitalSignature</li>
	 * <li>keyEncipherment</li>
	 * <li>id_kp_clientAuth</li>
	 * <li>id_kp_serverAuth</li>
	 * </ul>
	 * <p>
	 * 
	 * @param csr
	 *            the {@link org.bouncycastle.pkcs.PKCS10CertificationRequest
	 *            <em>PKCS10CertificationRequest</em>} to sign
	 * @param ca
	 *            the issuing {@link eu.mf2c.stfc.util.CA <em>CA</em>}
	 * @return the generated {@link java.security.cert.X509Certificate <em>X509certificate</em>} if successful
	 * @throws Exception
	 *             on error
	 */
	public static X509Certificate signCSR(PKCS10CertificationRequest csr, CA ca) throws Exception {
		//
		JcaPKCS10CertificationRequest jcaCSR = new JcaPKCS10CertificationRequest(csr);
		X500Name name = jcaCSR.getSubject();
		PublicKey subPK = jcaCSR.getPublicKey();
		//
		return generateCertificate(name, subPK, ca);
	}

	/**
	 * Wrapper method to get an end&#45;entity X.509 Certificate.
	 * <p>
	 * 
	 * @param cn
	 *            a {@link java.lang.String <em>String</em>} representation of the
	 *            subject principle name
	 * @param subPK
	 *            {@link java.security.PublicKey <em>PublicKey</em>} of the subject
	 *            principal
	 * @param ca
	 *            the issuing {@link eu.mf2c.stfc.util.CA <em>CA</em>}
	 * @return the generated {@link java.security.cert.X509Certificate <em>X509certificate</em>} if successful
	 * @throws Exception
	 *             on error
	 */
	public static X509Certificate generateCertificate(String cn, PublicKey subPK, CA ca) throws Exception {
		//
		return generateCertificate(
				new X500Name("CN=" + cn + ", OU=" + ca.toString().substring(0, 2) + "-FOG" + ", O=mF2C, C=EU "), subPK,
				ca);

	}

	/**
	 * Utility to generate an end&#45;entity X.509 Certificate. The following key
	 * usages and extended key usages are set&#58;
	 * <ul>
	 * <li>dataEncipherment</li>
	 * <li>digitalSignature</li>
	 * <li>keyEncipherment</li>
	 * <li>id_kp_clientAuth</li>
	 * <li>id_kp_serverAuth</li>
	 * </ul>
	 * <p>
	 * 
	 * @param subject
	 *            an {@link org.bouncycastle.asn1.x500.X500Name <em>X500Name</em>}
	 *            of the subject principal
	 * @param subPK
	 *            {@link java.security.PublicKey <em>PublicKey</em>} of the subject
	 *            principal
	 * @param ca
	 *            the issuing {@link eu.mf2c.stfc.util.CA <em>CA</em>}
	 * @return the generated {@link java.security.cert.X509Certificate <em>X509certificate</em>} if successful
	 * @throws Exception
	 *             on error
	 */
	public static X509Certificate generateCertificate(X500Name subject, PublicKey subPK, CA ca) throws Exception {
		X509Certificate x509 = null;
		// load the ca key and ca cert
		X509Certificate caCert = loadCert(ca.toString().toLowerCase() + ".pem");
		PrivateKey caKey = loadPrivateKey((ca.toString().substring(0, 3)).toLowerCase() + "ca.key");
		//
		LocalDate startDate = LocalDate.now();
		// end date 1 year from now
		Period period = Period.ofYears(1);
		LocalDate endDate = startDate.plus(period);

		//
		JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
				new JcaX509CertificateHolder(caCert).getSubject(), // issuer
				new java.math.BigInteger(String.valueOf(Instant.now().getEpochSecond())), // serial #
				Date.from(startDate.atStartOfDay(ZoneOffset.UTC).toInstant()),
				Date.from(endDate.atStartOfDay(ZoneOffset.UTC).toInstant()), subject, // holder
				subPK);// subject PK info
		JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
		// add the required usages
		certBuilder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(caCert));
		certBuilder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(subPK));
		// add the constraints, make this an end entity certificate
		certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
		// key usages based on example from Cheney's CAs
		KeyUsage keyUsage = new KeyUsage(
				KeyUsage.digitalSignature | KeyUsage.dataEncipherment | KeyUsage.keyEncipherment);
		certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
		ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(
				new KeyPurposeId[] { KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth });
		certBuilder.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);
		// build BouncyCastle certificate
		ContentSigner signer;
		//
		signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(caKey);
		X509CertificateHolder holder = certBuilder.build(signer);
		// check the extension
		// Extensions exts = holder.getExtensions();
		System.out.println("About to convert to JRE cert...");
		logger.debug("About to convert to JRE cert...");
		// convert to JRE certificate
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
		converter.setProvider(new BouncyCastleProvider());
		System.out.println("About to sign cert...");
		logger.debug("About to sign cert...");
		x509 = converter.getCertificate(holder);
		//
		// check the certificate was signed with the private key associated with the
		// provided public key
		x509.verify(caCert.getPublicKey());
		logger.debug("successfully verified new certificate using the CA public key");
		// check the extensions
		// boolean[] exts = x509.getKeyUsage();
		//
		// checkCertificate(x509); //
		// writeCertPEM2File(x509, "src\\main\\resources\\x509.pem");

		return x509;
	}

	/**
	 * Utility to print out the following attributes in the 
	 * {@link java.security.cert.X509Certificate <em>X509certificate</em>}&#58;
	 * <ul>
	 * <li>subject DN</li>
	 * <li>issuer DN</li>
	 * <li>basic constraint</li>
	 * <li>basic constraint</li>
	 * <li>key usages</li>
	 * <li>extended key usages</li>
	 * </ul>
	 * <p>
	 * 
	 * @param cert
	 *            the {@link java.security.cert.X509Certificate <em>X509certificate</em>} to check.
	 */
	public static void spotCheckCert(X509Certificate cert) {
		// can also use simple cert.toString() to print the content

		System.out.println("dn : " + cert.getSubjectX500Principal().getName());
		System.out.println("Issuer dn : " + cert.getIssuerX500Principal().getName());
		logger.info("dn : " + cert.getSubjectX500Principal().getName());
		logger.info("Issuer dn : " + cert.getIssuerX500Principal().getName());
		try {
			X509CertificateHolder certHolder = new X509CertificateHolder(cert.getEncoded());
			Extensions exts = certHolder.getExtensions();
			listExtension(exts);
			System.out.println("Is CA: " + (BasicConstraints.fromExtensions(exts)).isCA());
			logger.info("Is CA: " + (BasicConstraints.fromExtensions(exts)).isCA());
		} catch (CertificateEncodingException | IOException e) {
			System.out.println("Exception converting X.509 : " + e.getMessage());
			logger.info("Exception converting X.509 : " + e.getMessage());
		}
	}

	/**
	 * Utility to list the extension attributes in the Certification Request.
	 * <p>
	 * 
	 * @param attrs
	 *            Array of attributes to list.
	 */
	public static void listCSRExtensions(Attribute[] attrs) {
		// caller already checked for null and nil
		for (Attribute attr : attrs) {
			Extensions extensions = Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
			KeyUsage ku = KeyUsage.fromExtensions(extensions);
			if (ku == null) {
				logger.info("No keyusage found in CSR");
			} else {
				// System.out.println("KeyUsages: " + ku.toString()); this prints the object id
				logger.info("keyUsage has data enciperhment: " + ku.hasUsages(KeyUsage.dataEncipherment));
				logger.info("keyUsage has digital Signature : " + ku.hasUsages(KeyUsage.digitalSignature));
				logger.info("keyUsage has key enciperhment: " + ku.hasUsages(KeyUsage.keyEncipherment));
				logger.info("keyUsage has key cert sign: " + ku.hasUsages(KeyUsage.keyCertSign));
			}
			ExtendedKeyUsage eku = ExtendedKeyUsage.fromExtensions(extensions);
			if (eku != null) {
				// System.out.println("ExtendedKeyUsages: " + eku.toString()); this prints the
				// object id
				logger.info("ExtendedkeyUsage has purposeId clientAuth: "
						+ eku.hasKeyPurposeId(KeyPurposeId.id_kp_clientAuth));
				logger.info("ExtendedkeyUsage has purposeId serverAuth: "
						+ eku.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth));
			} else {
				logger.info("No ExtendedKeyusage found in CSR");
			}
			BasicConstraints bc = BasicConstraints.fromExtensions(extensions);
			if (bc != null) {
				logger.info("isCA : " + bc.isCA());
				if (bc.isCA()) {
					logger.info(bc.getPathLenConstraint());
				}
				logger.info("BC: " + bc.toString());
			} else {
				logger.info("No BasicConstraints found in CSR");
			}
		} // endfor
	}

	/**
	 * Utility to list the extended and key usages in an X.509 certificate.
	 * <p>
	 * 
	 * @param exts
	 *            certificate {@link org.bouncycastle.asn1.x509.Extensions
	 *            <em>Extensions</em>} object
	 */
	public static void listExtension(Extensions exts) {
		if (exts != null) {
			KeyUsage ku = KeyUsage.fromExtensions(exts);
			if (ku != null) {
				logger.info("keyUsage has data enciperhment: " + ku.hasUsages(KeyUsage.dataEncipherment));
				logger.info("keyUsage has digital Signature : " + ku.hasUsages(KeyUsage.digitalSignature));
				logger.info("keyUsage has key enciperhment: " + ku.hasUsages(KeyUsage.keyEncipherment));
				logger.info("keyUsage has key cert sign: " + ku.hasUsages(KeyUsage.keyCertSign));
			} else {
				logger.info("key usage is null!");
			}
			ExtendedKeyUsage eku = ExtendedKeyUsage.fromExtensions(exts);
			if (eku != null) {
				KeyPurposeId[] ekus = eku.getUsages();
				logger.info("keyPurposeId = " + ekus.length);
				for (KeyPurposeId kpid : ekus) {
					logger.info("ExtendedkeyUsage contains: " + kpid.getId());
				}
			} else {
				logger.info("Extended key usage is null!");
			}
		} else {
			logger.info("cert exten is null!");
		}
	}
	/**
	 * Convert an {@link org.bouncycastle.pkcs.PKCS10CertificationRequest
	 *            <em>PKCS10CertificationRequest</em>} object to {@link java.lang.String <em>String</em>}
	 *            representation
	 * @param csr	the {@link org.bouncycastle.pkcs.PKCS10CertificationRequest <em>PKCS10CertificationRequest</em>} object
	 * @return	the converted {@link java.lang.String <em>String</em>}
	 *            representation
	 * @throws IOException	on error reading in the object
	 */
	public static String getCSRString(PKCS10CertificationRequest csr) throws IOException {
		StringWriter sw = new StringWriter();
		JcaPEMWriter pw = new JcaPEMWriter(sw);
		pw.writeObject(csr);
		pw.flush();
		//
		logger.debug("The CSR: \n");
		logger.debug(sw.toString());
		pw.close();
		return sw.toString();		
	}

	/**
	 * @param args
	 * 
	 *            public static void main(String[] args) { // TODO Auto-generated
	 *            method stub
	 * 
	 *            }
	 */

}
