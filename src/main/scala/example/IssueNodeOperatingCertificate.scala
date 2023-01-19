package example

import com.amazonaws.auth.AWSCredentials
import com.amazonaws.auth.profile.ProfileCredentialsProvider
import com.amazonaws.client.builder.AwsClientBuilder
import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration
import com.amazonaws.auth.AWSStaticCredentialsProvider

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.Arrays
import java.util.Base64
import java.util.List
import java.util.Objects

import com.amazonaws.services.acmpca.AWSACMPCA
import com.amazonaws.services.acmpca.AWSACMPCAClientBuilder

import com.amazonaws.services.acmpca.model.ASN1Subject
import com.amazonaws.services.acmpca.model.ApiPassthrough
import com.amazonaws.services.acmpca.model.CustomAttribute
import com.amazonaws.services.acmpca.model.CustomExtension
import com.amazonaws.services.acmpca.model.Extensions
import com.amazonaws.services.acmpca.model.IssueCertificateRequest
import com.amazonaws.services.acmpca.model.IssueCertificateResult
import com.amazonaws.services.acmpca.model.SigningAlgorithm
import com.amazonaws.services.acmpca.model.Validity

import com.amazonaws.AmazonClientException
import com.amazonaws.services.acmpca.model.LimitExceededException
import com.amazonaws.services.acmpca.model.ResourceNotFoundException
import com.amazonaws.services.acmpca.model.InvalidStateException
import com.amazonaws.services.acmpca.model.InvalidArnException
import com.amazonaws.services.acmpca.model.InvalidArgsException
import com.amazonaws.services.acmpca.model.MalformedCSRException

import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.jce.X509KeyUsage

object IssueNodeOperatingCertificate {
  def stringToByteBuffer(s: String) =
    Option(s).map(s => ByteBuffer.wrap(s.getBytes(StandardCharsets.UTF_8)))

  def generateExtendedKeyUsageValue = {
    val keyPurposeIds = Array(
      KeyPurposeId.id_kp_clientAuth,
      KeyPurposeId.id_kp_serverAuth
    )
    val eku = new ExtendedKeyUsage(keyPurposeIds)
    val ekuBytes = eku.getEncoded

    Base64.getEncoder.encodeToString(ekuBytes)
  }

  def generateKeyUsageValue = {
    val keyUsage = new KeyUsage(X509KeyUsage.digitalSignature)
    val kuBytes = keyUsage.getEncoded

    Base64.getEncoder.encodeToString(kuBytes)
  }

  def main(args: Array[String]): Unit = {
    // Retrieve your credentials from the C:\Users\name\.aws\credentials file
    // in Windows or the .aws/credentials file in Linux.
    val credentials = new ProfileCredentialsProvider("default").getCredentials

    // Define the endpoint for your sample.
    val endpointRegion = "region" // Substitute your region here, e.g. "ap-southeast-2"
    val endpointProtocol = "https://acm-pca." + endpointRegion + ".amazonaws.com/"
    val endpoint =
      new AwsClientBuilder.EndpointConfiguration(endpointProtocol, endpointRegion)

    // Create a client that you can use to make requests.
    val client = AWSACMPCAClientBuilder.standard
      .withEndpointConfiguration(endpoint)
      .withCredentials(new AWSStaticCredentialsProvider(credentials))
      .build

    // Create a certificate request:
    val req = new IssueCertificateRequest

    // Set the CA ARN.
    req.withCertificateAuthorityArn("arn:aws:acm-pca:region:123456789012:certificate-authority/12345678-1234-1234-1234-123456789012");

    // Specify the certificate signing request (CSR) for the certificate to be signed and issued.
    val strCSR =
      "-----BEGIN CERTIFICATE REQUEST-----\n" +
      "base64-encoded certificate\n" +
      "-----END CERTIFICATE REQUEST-----\n";
    val csrByteBuffer: ByteBuffer = stringToByteBuffer(strCSR).orNull
    req.setCsr(csrByteBuffer)

    // Specify the template for the issued certificate.
    req.withTemplateArn("arn:aws:acm-pca:::template/BlankEndEntityCertificate_CriticalBasicConstraints_APIPassthrough/V1")

    // Set the signing algorithm.
    req.withSigningAlgorithm(SigningAlgorithm.SHA256WITHECDSA)

    // Set the validity period for the certificate to be issued.
    val validity = new Validity
    validity.withValue(10L)
    validity.withType("DAYS")
    req.withValidity(validity)

    // Set the idempotency token.
    req.setIdempotencyToken("1234")

    // Define custom attributes
    val customAttributes = Arrays.asList(
      (new CustomAttribute)
        .withObjectIdentifier("1.3.6.1.4.1.37244.1.1")
        .withValue("DEDEDEDE00010001"),
      (new CustomAttribute)
        .withObjectIdentifier("1.3.6.1.4.1.37244.1.5")
        .withValue("FAB000000000001D")
    )

    // Define a cert subject.
    val subject = new ASN1Subject
    subject.setCustomAttributes(customAttributes)

    val apiPassthrough = new ApiPassthrough
    apiPassthrough.setSubject(subject)

    // Generate Base64 encoded extension value for ExtendedKeyUsage
    val base64EncodedKUValue = generateKeyUsageValue

    // Generate custom extension
    val customKeyUsageExtension = new CustomExtension
    customKeyUsageExtension.setObjectIdentifier("2.5.29.15")
    customKeyUsageExtension.setValue(base64EncodedKUValue)
    customKeyUsageExtension.setCritical(true)

    // Generate Base64 encoded extension value for ExtendedKeyUsage
    val base64EncodedEKUValue = generateExtendedKeyUsageValue

    val customExtendedKeyUsageExtension = new CustomExtension
    customExtendedKeyUsageExtension.setObjectIdentifier("2.5.29.37") // ExtendedKeyUsage Extension OID
    customExtendedKeyUsageExtension.setValue(base64EncodedEKUValue)
    customExtendedKeyUsageExtension.setCritical(true)

    // Set KeyUsage and ExtendedKeyUsage extension to api-passthrough
    val extensions = new Extensions
    extensions.setCustomExtensions(Arrays.asList(customKeyUsageExtension, customExtendedKeyUsageExtension))
    apiPassthrough.setExtensions(extensions)
    req.setApiPassthrough(apiPassthrough)

    // Issue the certificate.
    val result = client.issueCertificate(req)

    // Retrieve and display the certificate ARN.
    val arn = result.getCertificateArn
    println(arn)
  }
}
