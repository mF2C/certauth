'''
A basic python client to demonstrate how to POST a CSR 
over SSL/TLS for an untrusted CA to sign

Created on 25 Jan 2019

@author: Shirley Crompton
'''
import httplib2
import os

class MyCAClient(object):
    '''
    An example Python3 client to interact with an untrusted CA
    '''


    def __init__(self):
        '''
        Constructor
        '''
        print(httplib2.__version__)
        print(httplib2.__copyright__)
        '''
        !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        #You must provide paths to your local certificates
        !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        '''
        cert_folder = "c:\\OpenSSL-Win64\\output\\"
        ca_cert = os.path.join(cert_folder, "it2TrustedCA.pem")
        client_cert = os.path.join(cert_folder, "ddscd0003.pem")
        client_key = os.path.join(cert_folder,"ddscd0003.key")
        self._ca_domain = "https://213.205.14.13:54443/certauths/rest/uc2untrustedca"
        #self._ca_domain = "https://localhost:8443/certauths/rest/uc2untrustedca"
        #create the client
        self._https = httplib2.Http(disable_ssl_certificate_validation=True)
        self._https.ca_certs = ca_cert        
        self._https.add_certificate(client_key, client_cert, self._ca_domain)
        
    #return the CSR String object
    def getCSR(self):
        return '''-----BEGIN CERTIFICATE REQUEST-----
        MIIC0DCCAbgCAQAwOjELMAkGA1UEBhMCRVUxDTALBgNVBAoTBG1GMkMxDTALBgNV
        BAsTBFNURkMxDTALBgNVBAMTBENBVTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
        ggEKAoIBAQC4UNYZgSlDiKELUi2KFw9wFrpvNCjKBEUAXWj9vvZgO5AQtOXYyTC7
        CR5J6hhZOv5qZpZeLwKh16nKl5ktftft/E/ph6qe44R6cf7ZuZGUFDgrBuzI1QvF
        AmJxAo/uJ5SEKQHAXmlw2HfI6FKsVbrfQB6cSXKQArQiyzUEBdLTXum/iabtMXWn
        br5T3GymJkPAh0bQd2C/niKf9T6V8CkgdIPwNHK3Qcjh7lUrMITONKa+HrOmP948
        xgP40Z4fMBZVtXRIGIxsp7Y4ZksEqnBiUSgleTKvhvYOzbd0tENGTvX4FxFOxJkJ
        CQA/aGj/85aZf/9bQBRO1Z915VgPtVR3AgMBAAGgUTBPBgkqhkiG9w0BCQ4xQjBA
        MA4GA1UdDwEB/wQEAwIEsDAMBgNVHRMBAf8EAjAAMCAGA1UdJQEB/wQWMBQGCCsG
        AQUFBwMCBggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAQEAra85deBwfzZR9DrO
        9SNxy659Hh5aKuBwufVhlFXtUNh8lW8OIk8sJMy8L4Ewl0xyJ2rhRcUqg/cV88oU
        NkXVnzEQQmzNr6TAvRwGuWWy36rBABlxehHDgt0Y1MF+O1Ql64yC2b/upxNtz3bC
        hs9QicST2B3O5ubTxlm01WAirgxTvSn8WqWZsuMwLXGNVa3fRpN/2Rv2DyjnmFOT
        xU7IlRIlab7VmfubOuuCv+oyP5YAD87iPHETXndC5WCShblIpwhe1nolvLozPHvS
        1v5QMFvYNFA6JLoy6uEYx97n+/3fCIIEOYBBMQkqycO0wMfYL2kib6pvHsH8qu6O
        ONiyWg==
        -----END CERTIFICATE REQUEST-----
        '''   
        
    def doSSLPost(self):
        '''
        Post a CSR over HTTPS for the untrusted CA to sign.
        An X.509 certificate should be returned.
        You need to provide your certificates in the init block
        for this to run        
        '''       
        response, content = self._https.request(self._ca_domain,
            'POST', headers={'content-type': 'text/plain','accept': 'text/plain'},body=self.getCSR())
        print("Response from CA: " + str(response) + " || content: " + content.decode() )
        
        '''
        OpenSSL> x509 -in ../output/testSSLService.pem -text
        Certificate:
            Data:
                Version: 3 (0x2)
                Serial Number: 1548938771 (0x5c52ee13)
            Signature Algorithm: sha256WithRSAEncryption
                Issuer: C=EU, ST=Sardegna, L=Cagliari, O=mF2C, OU=UC2-FOG, CN=UC2-UntrustedCA/emailAddress=shirley.crompton@stfc.ac.uk
                Validity
                    Not Before: Jan 31 00:00:00 2019 GMT
                    Not After : Jan 31 00:00:00 2020 GMT
                Subject: C=EU, O=mF2C, OU=STFC, CN=CAU1
                Subject Public Key Info:
                    Public Key Algorithm: rsaEncryption
                        Public-Key: (2048 bit)
                        Modulus:
                            00:b8:50:d6:19:81:29:43:88:a1:0b:52:2d:8a:17:
                            0f:70:16:ba:6f:34:28:ca:04:45:00:5d:68:fd:be:
                            f6:60:3b:90:10:b4:e5:d8:c9:30:bb:09:1e:49:ea:
                            18:59:3a:fe:6a:66:96:5e:2f:02:a1:d7:a9:ca:97:
                            99:2d:7e:d7:ed:fc:4f:e9:87:aa:9e:e3:84:7a:71:
                            fe:d9:b9:91:94:14:38:2b:06:ec:c8:d5:0b:c5:02:
                            62:71:02:8f:ee:27:94:84:29:01:c0:5e:69:70:d8:
                            77:c8:e8:52:ac:55:ba:df:40:1e:9c:49:72:90:02:
                            b4:22:cb:35:04:05:d2:d3:5e:e9:bf:89:a6:ed:31:
                            75:a7:6e:be:53:dc:6c:a6:26:43:c0:87:46:d0:77:
                            60:bf:9e:22:9f:f5:3e:95:f0:29:20:74:83:f0:34:
                            72:b7:41:c8:e1:ee:55:2b:30:84:ce:34:a6:be:1e:
                            b3:a6:3f:de:3c:c6:03:f8:d1:9e:1f:30:16:55:b5:
                            74:48:18:8c:6c:a7:b6:38:66:4b:04:aa:70:62:51:
                            28:25:79:32:af:86:f6:0e:cd:b7:74:b4:43:46:4e:
                            f5:f8:17:11:4e:c4:99:09:09:00:3f:68:68:ff:f3:
                            96:99:7f:ff:5b:40:14:4e:d5:9f:75:e5:58:0f:b5:
                            54:77
                        Exponent: 65537 (0x10001)
                X509v3 extensions:
                    X509v3 Authority Key Identifier:
                        keyid:27:0A:B7:5A:06:C1:08:1A:AB:22:F1:D0:9F:61:9C:E1:34:65:8D:05
                        DirName:/C=EU/ST=Sardegna/L=Cagliari/O=mF2C/OU=UC2-FOG/CN=UC2-UntrustedCA/emailAddress=shirley.crompton@stfc.ac.uk
                        serial:A2:54:31:4D:D1:CD:99:DA
        
                    X509v3 Subject Key Identifier:
                        70:9C:79:54:6A:56:8A:93:17:F6:0D:C7:6A:C6:C4:C8:A3:97:2C:33
                    X509v3 Basic Constraints: critical
                        CA:FALSE
                    X509v3 Key Usage: critical
                        Digital Signature, Key Encipherment, Data Encipherment
                    X509v3 Extended Key Usage:
                        TLS Web Client Authentication, TLS Web Server Authentication
            Signature Algorithm: sha256WithRSAEncryption
                 6a:7b:2a:8f:95:ec:1a:8d:a8:35:4f:39:b3:ae:20:b4:71:ff:
                 57:08:48:09:41:a3:2f:42:9c:c5:7d:a6:21:0b:f4:54:24:00:
                 d8:51:ce:20:63:dd:ff:a0:04:75:61:a3:2a:47:03:23:12:53:
                 52:e8:48:d8:bb:5a:6d:dd:4b:17:65:0a:c9:42:44:f7:48:e0:
                 13:62:c0:2b:e2:32:ba:a1:fd:1e:00:5f:6d:ac:13:c2:f4:4f:
                 76:b1:95:d2:4f:f1:c2:7d:00:49:6f:05:f6:45:ce:f1:f1:ee:
                 d3:df:1c:cb:9a:fd:63:4e:40:31:25:4b:86:0a:d8:48:df:28:
                 1d:fe:24:3d:b1:20:11:3e:93:f1:1a:18:3a:98:07:92:97:53:
                 2a:9a:d6:3f:5b:3b:db:66:22:d0:60:94:b5:2a:f0:fc:76:a4:
                 70:73:cb:ee:46:e0:f4:13:d0:26:a9:cd:94:3b:c1:9c:cc:d7:
                 90:84:48:6b:8a:07:27:69:54:8c:1e:9e:35:44:82:bd:ee:22:
                 d8:9d:49:e2:ac:68:44:89:6a:20:f3:d3:f4:f3:82:70:75:5b:
                 a7:61:15:12:7f:72:31:24:42:a5:17:04:63:57:87:82:cf:e8:
                 bf:37:01:e1:bd:16:8a:43:19:d0:91:99:52:58:38:d0:c2:38:
                 89:ba:27:65
        -----BEGIN CERTIFICATE-----
        MIIEhzCCA2+gAwIBAgIEXFLuEzANBgkqhkiG9w0BAQsFADCBmjELMAkGA1UEBhMC
        RVUxETAPBgNVBAgMCFNhcmRlZ25hMREwDwYDVQQHDAhDYWdsaWFyaTENMAsGA1UE
        CgwEbUYyQzEQMA4GA1UECwwHVUMyLUZPRzEYMBYGA1UEAwwPVUMyLVVudHJ1c3Rl
        ZENBMSowKAYJKoZIhvcNAQkBFhtzaGlybGV5LmNyb21wdG9uQHN0ZmMuYWMudWsw
        HhcNMTkwMTMxMDAwMDAwWhcNMjAwMTMxMDAwMDAwWjA6MQswCQYDVQQGEwJFVTEN
        MAsGA1UEChMEbUYyQzENMAsGA1UECxMEU1RGQzENMAsGA1UEAxMEQ0FVMTCCASIw
        DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALhQ1hmBKUOIoQtSLYoXD3AWum80
        KMoERQBdaP2+9mA7kBC05djJMLsJHknqGFk6/mpmll4vAqHXqcqXmS1+1+38T+mH
        qp7jhHpx/tm5kZQUOCsG7MjVC8UCYnECj+4nlIQpAcBeaXDYd8joUqxVut9AHpxJ
        cpACtCLLNQQF0tNe6b+Jpu0xdaduvlPcbKYmQ8CHRtB3YL+eIp/1PpXwKSB0g/A0
        crdByOHuVSswhM40pr4es6Y/3jzGA/jRnh8wFlW1dEgYjGyntjhmSwSqcGJRKCV5
        Mq+G9g7Nt3S0Q0ZO9fgXEU7EmQkJAD9oaP/zlpl//1tAFE7Vn3XlWA+1VHcCAwEA
        AaOCATIwggEuMIHPBgNVHSMEgccwgcSAFCcKt1oGwQgaqyLx0J9hnOE0ZY0FoYGg
        pIGdMIGaMQswCQYDVQQGEwJFVTERMA8GA1UECAwIU2FyZGVnbmExETAPBgNVBAcM
        CENhZ2xpYXJpMQ0wCwYDVQQKDARtRjJDMRAwDgYDVQQLDAdVQzItRk9HMRgwFgYD
        VQQDDA9VQzItVW50cnVzdGVkQ0ExKjAoBgkqhkiG9w0BCQEWG3NoaXJsZXkuY3Jv
        bXB0b25Ac3RmYy5hYy51a4IJAKJUMU3RzZnaMB0GA1UdDgQWBBRwnHlUalaKkxf2
        DcdqxsTIo5csMzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIEsDAdBgNVHSUE
        FjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggEBAGp7Ko+V
        7BqNqDVPObOuILRx/1cISAlBoy9CnMV9piEL9FQkANhRziBj3f+gBHVhoypHAyMS
        U1LoSNi7Wm3dSxdlCslCRPdI4BNiwCviMrqh/R4AX22sE8L0T3axldJP8cJ9AElv
        BfZFzvHx7tPfHMua/WNOQDElS4YK2EjfKB3+JD2xIBE+k/EaGDqYB5KXUyqa1j9b
        O9tmItBglLUq8Px2pHBzy+5G4PQT0CapzZQ7wZzM15CESGuKBydpVIwenjVEgr3u
        ItidSeKsaESJaiDz0/TzgnB1W6dhFRJ/cjEkQqUXBGNXh4LP6L83AeG9FopDGdCR
        mVJYONDCOIm6J2U=
        -----END CERTIFICATE-----                                     
        '''        
    def doSSLGet(self):
        '''
        Simple get to test if the endpoint is live
        '''
        content = self._https.request(self._ca_domain,
                       method="GET")[1]   
        print(content.decode())
        #Hello, you are trying to get this ca: uc2untrustedca.  Only post method supported.
        
myClient = MyCAClient()
myClient.doSSLGet() #over https port 54443
myClient.doSSLPost() #https port 54443

