'''
A basic python client to demonstrate how to POST a CSR for
an untrusted CA to sign

Created on 9 Jan 2019

@author: Shirley Crompton
'''
import httplib2

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
        #create the client
        self._http = httplib2.Http()
        
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
        -----END CERTIFICATE REQUEST-----'''   
        
    def doPost(self):
        '''
        Post a CSR for the untrusted CA to sign.
        An X.509 certificate should be returned.
        '''  
        response, content = self._http.request("http://213.205.14.13:8080/certauths/rest/uc2untrustedca",
            'POST', headers={'content-type': 'text/plain','accept': 'text/plain'},body=self.getCSR())
        print("Response from CA: " + str(response) + " || content: " + content.decode() )
        '''
        The content viewed using openSSL:
        OpenSSL> x509 -in c:\OpenSSL-Win64\output\pythonOutput.pem -text
        Certificate:
            Data:
                Version: 3 (0x2)
                Serial Number: 1547049608 (0x5c361a88)
            Signature Algorithm: sha256WithRSAEncryption
                Issuer: C=EU, ST=Sardegna, L=Cagliari, O=mF2C, OU=UC2-FOG, CN=UC2-UntrustedCA/emailAddress=shirley.crompton@stfc.ac.uk
                Validity
                    Not Before: Jan  9 00:00:00 2019 GMT
                    Not After : Jan  9 00:00:00 2020 GMT
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
                 be:bf:7f:21:83:67:f5:0f:b9:7c:03:c8:e4:af:be:58:0f:4a:
                 46:ec:3b:ed:b8:07:d4:b6:61:af:02:7d:c5:51:9f:bf:7a:d7:
                 fa:ea:f7:d7:8d:c7:68:eb:3d:04:b7:d4:a5:cf:d4:3f:46:e0:
                 eb:07:bf:1f:c5:46:75:5c:a5:39:6b:03:d2:98:1d:cd:9d:72:
                 de:44:92:c5:a0:e2:e7:e7:f9:e4:95:ac:a7:cf:af:59:f7:cc:
                 73:ac:6d:33:e3:4a:06:2c:67:09:74:c1:8c:d4:0c:6e:f1:da:
                 03:b4:9b:8f:ba:e5:14:47:ab:56:b6:a5:d0:64:79:13:9e:3a:
                 a5:f0:d4:50:3d:5b:a6:e4:1b:e9:10:0c:f2:aa:d1:70:6f:12:
                 d1:e0:27:be:1e:de:aa:a2:5d:f8:b4:9f:a6:77:3f:77:7f:4d:
                 13:d4:19:99:11:91:94:9b:61:68:04:6f:61:63:a1:9b:23:f6:
                 13:32:96:3c:45:c1:13:5f:d1:00:3f:9a:00:7e:48:b7:0a:52:
                 28:f6:af:33:a0:99:40:8f:f7:69:2e:cc:97:e6:50:a6:51:29:
                 9a:7a:8a:33:77:d4:c0:4d:fd:2e:4a:fd:18:7f:c5:2a:64:1a:
                 c4:19:e5:a0:b2:1c:81:33:db:f8:09:b1:c1:d2:36:67:c8:26:
                 5e:e7:b4:76
        -----BEGIN CERTIFICATE-----
        MIIEhzCCA2+gAwIBAgIEXDYaiDANBgkqhkiG9w0BAQsFADCBmjELMAkGA1UEBhMC
        RVUxETAPBgNVBAgMCFNhcmRlZ25hMREwDwYDVQQHDAhDYWdsaWFyaTENMAsGA1UE
        CgwEbUYyQzEQMA4GA1UECwwHVUMyLUZPRzEYMBYGA1UEAwwPVUMyLVVudHJ1c3Rl
        ZENBMSowKAYJKoZIhvcNAQkBFhtzaGlybGV5LmNyb21wdG9uQHN0ZmMuYWMudWsw
        HhcNMTkwMTA5MDAwMDAwWhcNMjAwMTA5MDAwMDAwWjA6MQswCQYDVQQGEwJFVTEN
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
        FjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggEBAL6/fyGD
        Z/UPuXwDyOSvvlgPSkbsO+24B9S2Ya8CfcVRn7961/rq99eNx2jrPQS31KXP1D9G
        4OsHvx/FRnVcpTlrA9KYHc2dct5EksWg4ufn+eSVrKfPr1n3zHOsbTPjSgYsZwl0
        wYzUDG7x2gO0m4+65RRHq1a2pdBkeROeOqXw1FA9W6bkG+kQDPKq0XBvEtHgJ74e
        3qqiXfi0n6Z3P3d/TRPUGZkRkZSbYWgEb2FjoZsj9hMyljxFwRNf0QA/mgB+SLcK
        Uij2rzOgmUCP92kuzJfmUKZRKZp6ijN31MBN/S5K/Rh/xSpkGsQZ5aCyHIEz2/gJ
        scHSNmfIJl7ntHY=
        -----END CERTIFICATE-----
                                           
                                               
        '''                                       
                
    def doGet(self):
        '''
        Simple get to test if the endpoint is live
        '''
        content = self._http.request("http://213.205.14.13:8080/certauths/rest/it2trustedca",
                       method="GET")[1]   
        print(content.decode())
        #Hello, you are trying to get this ca: it2trustedca.  Only post method supported.
        
myClient = MyCAClient()
myClient.doGet()
myClient.doPost()

