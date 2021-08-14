using ComponentSpace.SAML2;
using ComponentSpace.SAML2.Assertions;
using ComponentSpace.SAML2.Protocols;
using System;
using System.Configuration;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace GenerateSAML
{

    

    public class SamlResponse
    {
        #region Public Methods
        public SSOParameters ssoParams;
        public SamlResponse(SSOParameters obj)
        {
            ssoParams = obj;
        }
        public string GetSAMLResponse(bool encrypt)
        {
            var response = "";
            try
            {
                //  SSOLog.CreateActivityLog(this.GetType().Name, MethodBase.GetCurrentMethod().Name, Constants.METHODSTARTED);
                SAMLResponse _samlResponse = new SAMLResponse();
                _samlResponse.Destination = ssoParams.Destination;
                Issuer _issuer = new Issuer(ssoParams.Issuer);
                _issuer.Format = ssoParams.IssuerFormat;
                _samlResponse.Issuer = _issuer;
                _samlResponse.Status = new Status(SAMLIdentifiers.PrimaryStatusCodes.Success, null);

                SAMLAssertion _samlAssertion = new SAMLAssertion();
                _samlAssertion.Issuer = _issuer;
                _samlAssertion.Subject = GetSubjectSamlAssertion();
                _samlAssertion.Conditions = GetConditionSamlAssertion();
                _samlAssertion.Statements.Add(GetAuthnStatementSamlAssertion());
                _samlAssertion.Statements.Add(GetAttributeStatement());


                X509Certificate2 _idpcertificate = new X509Certificate2(ssoParams.SigniningCertPath, ssoParams.SigniningCertPass);
                XmlElement _xmlElement = _samlAssertion.ToXml();
                // SAMLAssertionSignature.Generate(_xmlElement,_idpcertificate.PrivateKey,_idpcertificate);
                SAMLAssertionSignature.Generate(_xmlElement, _idpcertificate.PrivateKey, _idpcertificate,
                        null, ssoParams.SignatureUrl, ssoParams.SignatureRsaUrl);



                // Load the signing and encryption certificates.
                // The identity provider signs with it's private key.
                // The identity provider encrypts with the service provider's public key.
                // X509Certificate2 idpCertificate = new X509Certificate2(ssoParams.SigniningCertPath, ssoParams.SigniningCertPass,
                //     X509KeyStorageFlags.MachineKeySet);
                X509Certificate2 spCertificate = new X509Certificate2(ssoParams.EncryptionCertPath);

                // Construct a SAML assertion - details not shown.
                SAMLAssertion samlAssertion = new SAMLAssertion();
                samlAssertion.Issuer = new Issuer(ssoParams.Issuer);

                // Serialize to XML.
                //XmlElement xmlElement = _samlResponse.ToXml();

                // Sign the SAML assertion.
                SAMLAssertionSignature.Generate(_xmlElement, _idpcertificate.PrivateKey, _idpcertificate);

                // Encrypt the SAML assertion.
                if(encrypt)
                {
                EncryptedAssertion encryptedAssertion = new EncryptedAssertion(_xmlElement, spCertificate);
                _samlResponse.Assertions.Add(encryptedAssertion);
                }
                else
                  _samlResponse.Assertions.Add(_xmlElement);

                XmlElement RespXmlElement = _samlResponse.ToXml();

                //response = encryptedAssertion.ToXml().OuterXml.ToString();
                response = _samlResponse.ToXml().OuterXml.ToString();
            }
            catch (Exception ex)
            {
                // response.Status.StatusCode = EnumResponseCode.Error;
                // response.Status.ErrorMessage = ex.Message;
                // ex.CreateAndLogException(System.Diagnostics.TraceEventType.Error);
            }
            return response;
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Method to create the Subject of SAML Assertion
        /// </summary>
        /// <returns></returns>
        private Subject GetSubjectSamlAssertion()
        {
            // SSOLog.CreateActivityLog(this.GetType().Name, MethodBase.GetCurrentMethod().Name, Constants.METHODSTARTED);

            Subject _subject = new Subject(new NameID(ssoParams.NameID, null, null, ssoParams.NameIDFormat, null));
            SubjectConfirmation _subjectConfirmation = new SubjectConfirmation(SAMLIdentifiers.SubjectConfirmationMethods.Bearer);
            SubjectConfirmationData _subjectConfirmationData = new SubjectConfirmationData();
            _subjectConfirmationData.Recipient = ssoParams.Destination;
            _subjectConfirmationData.NotOnOrAfter = System.DateTime.UtcNow;//AddYears(5);
            _subjectConfirmationData.NotBefore = System.DateTime.UtcNow;//AddYears(-5);
            _subjectConfirmation.SubjectConfirmationData = _subjectConfirmationData;
            _subject.SubjectConfirmations.Add(_subjectConfirmation);
            // SSOLog.CreateActivityLog(this.GetType().Name, MethodBase.GetCurrentMethod().Name, Constants.METHODENDED);
            return _subject;
        }

        /// <summary>
        /// Method to create the Condition of SAML Assertion
        /// </summary>
        /// <returns></returns>
        private Conditions GetConditionSamlAssertion()
        {
            // SSOLog.CreateActivityLog(this.GetType().Name, MethodBase.GetCurrentMethod().Name, Constants.METHODSTARTED);
            Conditions _condition = new Conditions(System.DateTime.UtcNow, System.DateTime.UtcNow);
            AudienceRestriction _audienceRestriction = new AudienceRestriction();
            _audienceRestriction.Audiences.Add(new Audience(ssoParams.Audience));
            _condition.ConditionsList.Add(_audienceRestriction);
            //SSOLog.CreateActivityLog(this.GetType().Name, MethodBase.GetCurrentMethod().Name, Constants.METHODENDED);
            return _condition;
        }

        /// <summary>
        /// Method to create the AuthnStatement of SAML Assertion
        /// </summary>
        /// <returns></returns>
        private AuthnStatement GetAuthnStatementSamlAssertion()
        {
            // SSOLog.CreateActivityLog(this.GetType().Name, MethodBase.GetCurrentMethod().Name, Constants.METHODSTARTED);
            AuthnStatement _authnStatement = new AuthnStatement();
            _authnStatement.AuthnContext = new AuthnContext();
            _authnStatement.SessionNotOnOrAfter = System.DateTime.UtcNow;
            _authnStatement.AuthnContext.AuthnContextClassRef = new AuthnContextClassRef(SAMLIdentifiers.AuthnContextClasses.Password);
            // SSOLog.CreateActivityLog(this.GetType().Name, MethodBase.GetCurrentMethod().Name, Constants.METHODENDED);
            return _authnStatement;
        }

        /// <summary>
        /// Method to create the Attribute of SAML Assertion
        /// </summary>
        /// <returns></returns>
        private AttributeStatement GetAttributeStatement()
        {

            // SSOLog.CreateActivityLog(this.GetType().Name, MethodBase.GetCurrentMethod().Name, Constants.METHODSTARTED);
            AttributeStatement _attrStatement = new AttributeStatement();
            // SAMLAttribute _samlAttr1 = new SAMLAttribute(Constants.SOURCEID, null, null, "xs:string", sourceID);
            // SAMLAttribute _samlAttr2 = new SAMLAttribute(Constants.SITEID, null, null, "xs:string", siteID);
            // SAMLAttribute _samlAttr3 = new SAMLAttribute(Constants.DECODETYPE, null, null, "xs:string", decodeType);
            SAMLAttribute _samlAttr3 = new SAMLAttribute("mail", null, null, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "test given name");


            //  _attrStatement.Attributes.Add(_samlAttr1);
            // _attrStatement.Attributes.Add(_samlAttr2);
            _attrStatement.Attributes.Add(_samlAttr3);
            //  SSOLog.CreateActivityLog(this.GetType().Name, MethodBase.GetCurrentMethod().Name, Constants.METHODENDED);
            return _attrStatement;
        }

        private class BaseResponse<T>
        {
            public BaseResponse()
            {
            }

            public object ResponseData { get; set; }
            public object Status { get; set; }
        }
        #endregion
    }

    
}
