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
package eu.mf2c.stfc.rest;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import eu.mf2c.stfc.util.CA;
import eu.mf2c.stfc.util.CertUtil;

/**
 * The entry point to the mF2C cloud certificate authorities.
 * <p>
 * author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * Created 11 Dec 2018
 */
//you can use either / or not in the @Path definition
@Path("/{ca}") //url: host:port/certauths/rest/<ca>, the '/' seems optional here
public class CertAuthsRestService {
	final static Logger logger = LogManager.getLogger(CertAuthsRestService.class);
	//
	//@Path("/{ca}") //url: host:port/certauths/rest/<ca>
	@GET
	@Produces(MediaType.TEXT_PLAIN)
	public Response doGet(@PathParam("ca") String ca) {
		//
		logger.info("CertAuthsRestService's doGet() called for ca: " + ca);
		//need to check the requested ca
		if(validateCA(ca)) {
			return Response.ok("Hello, you are trying to get this ca: " + ca + ".  Only post method supported.").build();
		}else {
			return Response.status(404, "Sorry, no such " + ca + "!").build();
		}
		//return builder.build();	
	}
	//@Path("/{ca}")
	@POST
	@Consumes("text/plain")
	@Produces(MediaType.TEXT_PLAIN)
	public Response doPost(String content, @PathParam("ca") String ca) {
		//trim white space/s
		String input = content.trim();
		//need to check the requested ca
		if(validateCA(ca)) {
			logger.info("CertAuthsRestService's doPost() called for ca: " + ca);
			//then check if it is a trusted or untrusted ca
			if(ca.contains("untrustedca")) {//the post content should be an CSR
				//
				if(input.startsWith("-----BEGIN CERTIFICATE REQUEST")) {
					//go ahead
					try {
						X509Certificate cert = CertUtil.signCSR(CertUtil.loadCSR(input), CA.valueOf(ca.toUpperCase()));
						//convert to String
						String certStr = CertUtil.concateCredentials(null, cert); 
						return Response.ok(certStr).build();
					}catch(Exception e) {
						logger.error("Error processing CSR using " + ca + ": " + e.getMessage());
						return Response.status(500, "Error processing CSR using " + ca + ": " + e.getMessage()).build();
					}
				}else {//unsupported content
					return Response.status(400, "Sorry, you need to post a CSR string for " + ca + "!").build();
				}
			}else {//trusted, the content should be a CN, which is limited to 64 chars
				//
				try {
					if(input.length() > 65) {
						throw new Exception("CN exceeded 64 chars!  Cannot issue certificate....");
					}
					KeyPair kp = CertUtil.genKeyPair();
					X509Certificate trustedCert = CertUtil.generateCertificate(input, kp.getPublic(), CA.valueOf(ca.toUpperCase()));
					String credentials = CertUtil.concateCredentials(kp.getPrivate(), trustedCert);
					//
					return Response.ok(credentials).build();
				}catch(Exception e) {
					logger.error("Error getting certificate from " + ca + "! Error: " + e.getMessage());
					return Response.status(500, "Error getting certificate from " + ca + "! Error: " + e.getMessage()).build();
				}
			}
		}else {//invalid ca
			return Response.status(404, "Sorry, no such " + ca + "!").build();
		}		
	}
	
	/**
	 * Verify if the provide ca name string matches one of those defined in
	 * {@link eu.mf2c.stfc.util.CA <em>CA</em>}
	 * <p>
	 * @param ca	the CA String
	 * @return	true if the name is defined in {@link eu.mf2c.stfc.util.CA <em>CA</em>}, else false.
	 */
	private boolean validateCA(String ca) {
		//		
		List<CA> cas = Arrays.asList(CA.values());
		for(CA caEnum : cas) {
			if(caEnum.toString().equals(ca.toUpperCase())) {
				return true;
			}
		}//end for
		return false;			
	}
}
