# CertAuth (version 0.1 for IT-2)

## Description

This is a vanilla certification service written specifically to support the mF2C demonstration.  
It provides 8 different certification services:

- it2trustedca
- it2untrustedca
- uc1trustedca
- uc1untrustedca
- uc2trustedca
- uc2untrustedca
- uc3trustedca
- uc3untrustedca

Each CA is provisioned with its own sign-signed certificate and does not share a common root.
The *trustedca is used to issue X.509 v3 certificates for mF2C infrastructure components (e.g. CAUs)
The *untrustedca is used to issue X.509 v3 certificates for mF2C agents (as in IT1 demo).

The services are accessed via the following REST resource endpoint pattern:

	https://<host>:<port>/certauths/rest/<requiredCA>
	Example: https://it1demo.mf2c-project.eu:54443/certauths/rest/it2trustedca
	
Replace the requiredCA with the appropriate CA name.  Please use the exact name as listed above.

To get the certificate of the CA, clients should make a HTTP get query of the appropriate CA endpoint.
The CA will return its certificate as a PEM String. 

To use the *trustedca service, you post a CN (Commonname) String with the plain text mimetype.
The CN is restricted to 64 chars long.  An error will be thrown if the CN length exceeds 64 chars.
The service returns a plain text String which contains the RSA (2048 length) private key concatenated with the
X.509 certificate formatted in PEM.  Use a text editor to split them into separate file.  Each credentials
is prefixed with the standard header like -----BEGIN CERTIFICATE-----, -----BEGIN RSA PRIVATE KEY-----
You could also split them programmatically, see CertAuthRestServiceTest.verifyCertificate(String, CA, String) 
method for an example in JAVA.

To use the *untrustedca service, the CAU should post a CSR String with the plain text mimetype.
The service returns a plain text String which contains the issued certificate in PEM format.

At runtime, the CAs' private keys and certificate files need to be located at the host's \var\lib\certauths\ folder.
For security reason, these files are not bundled with the application but are stored in the mF2C owncloud repository
under mF2C\Working Folders\WP5 PoC integration\CA\CA credentials\ .

The mF2C certification service is an independent ReST service in the cloud that runs external to an Agent or an mF2C fog cluster.
The mF2C CAU middleware communicates with it over HTTPS.

## Building and Running

See the *vanilla-ca-howto.pdf* in the resources folder.

## Contributors

**Contributors to this repository agree to release their code under
the Apache 2.0 license.**

## License

Copyright by various contributors.  See individual source files for
copyright information.  

DISTRIBUTED under the [Apache License, Version 2.0 (January
2004)](http://www.apache.org/licenses/LICENSE-2.0).

## CHANGELOG

### 1.04 (29/07/2019)

Rewritten from IT1 version.  CAU-Client now runs a TCP-server to listen to requests from other blocks in the Agent. 

#### Added

 - 21/08/2019 Publish CA certificate function.
 
#### Changed

 - 24/06/2019 Replaced Tomcat server certificate and key 






