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
package eu.mf2c.stfc.ca;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import eu.mf2c.stfc.util.CA;
import eu.mf2c.stfc.util.CertUtil;

/**
 * Core functionalities for&#58;
 * <ul>
 * <li>requesting certificates</li>
 * <li>approving certificates</li>
 * <li>generating certificates, and</li>
 * <li>retrieving certificates</li>
 * </ul>
 * <p> * 
 * author Shirley Crompton
 * email shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group, UKRI Science and Technology Council
 * Created 11 Dec 2018
 */
public class CertAuthority {
	/** Message Logger */
	final static Logger logger = LogManager.getLogger(CertAuthority.class);

	/**
	 * Default constructor
	 */
	public CertAuthority() {
	}

	/**
	 * Generate the keys and {@link java.security.cert.X509Certificate <em>X509certificate</em>} for
	 * an mF2C infrastructure component.  A trusted certification authority is used.  The 
	 * {@link java.security.cert.X509Certificate <em>X509certificate</em>} and
	 * {@link java.security.PrivateKey <em>PrivateKey</em>} are concatenated together and written out
	 * in PEM format.
	 * <p>
	 * @param cn	the subject common name
	 * @param ca	the issuing {@link eu.mf2c.stfc.util.CA <em>CA</em>}
	 * @return	a {@link java.lang.String <em>String</em>} representation of the credentials.
	 * @throws Exception on processing error
	 */
	public String generateTrustCert(String cn, CA ca) throws Exception {
		if (cn == null || cn.isEmpty()) {
			throw new Exception("No CN provided.  Cannot generate certificate....");
		} else if (!ca.toString().contains("TRUSTED")) {
			throw new Exception("Incorrect ca(" + ca.toString() + "), only trusted CAs allowed....");
		} else {
			// go ahead, issue trusted certificate. can use '.' in a file name in both linux
			// and wins

			// first generate the keypair RSA 2048 length
			KeyPair keypair = CertUtil.genKeyPair();
			// create the certificate
			X509Certificate cert = CertUtil.generateCertificate(cn, keypair.getPublic(), ca);
			// concate them together
			return CertUtil.concateCredentials(keypair.getPrivate(), cert);
		}
	}
	/**
	 * Sign a {@link org.bouncycastle.pkcs.PKCS10CertificationRequest <em>PKCS10CertificationRequest</em>} 
	 * and generate an {@link java.security.cert.X509Certificate <em>X509certificate</em>} using the
	 * specified {@link eu.mf2c.stfc.util.CA <em>CA</em>}.  The {@link java.security.cert.X509Certificate <em>X509certificate</em>} 
	 * is written out in PEM format.
	 * <p>
	 * @param csr	a {@link org.bouncycastle.pkcs.PKCS10CertificationRequest <em>PKCS10CertificationRequest</em>}
	 * @param ca	the issuing {@link eu.mf2c.stfc.util.CA <em>CA</em>}
	 * @return	a {@link java.lang.String <em>String</em>} representation of the credential.
	 * @throws Exception  on processing error
	 */
	public String generateAgentCert(PKCS10CertificationRequest csr, CA ca) throws Exception {
		
		if(csr == null) {
			throw new Exception("The csr is null! Cannot proceed ....");
		}else if(!ca.toString().contains("UNTRUSTED")) {
			throw new Exception("Only untrusted CA can issue Agent certificates....");
		}else {//go ahead
			X509Certificate cert = CertUtil.signCSR(csr, ca);
			return CertUtil.concateCredentials(null, cert);
		}		
	}

}
