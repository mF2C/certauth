CertAuth (version 0.1 for IT-2)

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

Each CA is provisioned with its own sign-signed certificate and do not share a common root.
The *trustedca is used to issue X.509 v3 certificates for mF2C infrastructure components (e.g. CAUs)
The *untrustedca is used to issue X.509 v3 certificates for mF2C agents (as in IT1 demo).

The services are accessed via the following REST resource endpoint pattern:

	http://<host>:<port>/certauths/rest/<requiredCA>
	
Replace the requiredCA with the appropriate CA name.  Please use the exact name as listed above.

To use the *trustedca service, you post a CN (Commonname) String with the plain text mimetype.
The CN is restricted to 64 chars long.  An error will be thrown if the CN length exceeds 64 chars.
The service returns a plain text String which contains the RSA (2048 length) private key concatenated with the
X.509 certificate formatted in PEM.  Use a text editor to split them into separate file.  Each credentials
is prefixed with the standard header like -----BEGIN CERTIFICATE-----, -----BEGIN RSA PRIVATE KEY-----
You could also split them programmatically, see CertAuthRestServiceTest.verifyCertificate(String, CA, String) method
for an example in JAVA.

To use the *untrustedca service, the CAU should post a CSR String with the plain text mimetype.
The service returns a plain text String which contains the issued certificate in PEM format.

To bootstrap the demo, first obtain trusted certificates for your CAUs.  Install them together with the public keys of the 
issuing CA.  You also need to add the issuing CA public key to the CAU client.

At runtime, the CA private key and certificate files need to be located at the host's \var\lib\certauths\ folder.
These files (will be) are not bundled with the application but are stored in the mF2C owncloud at (somewhere).

Shirley Crompton
UKRI-STFC
19 December 2018

(This is a draft, I will correct the content after the holiday :)




