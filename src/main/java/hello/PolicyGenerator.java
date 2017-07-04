package hello;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * Created by georgit on 04/07/2017.
 */
public class PolicyGenerator
{
  public static void main(String[] args) throws Exception
  {
    String policy_document = "{\"expiration\":\"2015-12-30T12:00:00.000Z\",\"conditions\":[{\"bucket\":\"mynewdulibucket\"},[\"starts-with\",\"$key\",\"user/user1/\"],{\"acl\":\"public-read\"},{\"success_action_redirect\":\"http://mynewdulibucket.s3.amazonaws.com/successful_upload.html\"},[\"starts-with\",\"$Content-Type\",\"image/\"],{\"x-amz-meta-uuid\":\"14365123651274\"},{\"x-amz-server-side-encryption\":\"AES256\"},[\"starts-with\",\"$x-amz-meta-tag\",\"\"],{\"x-amz-credential\":\"AKIAJQHQNWQ7FCTGNKQQ/20151229/us-east-1/s3/aws4_request\"},{\"x-amz-algorithm\":\"AWS4-HMAC-SHA256\"},{\"x-amz-date\":\"20151229T000000Z\"}]}";
    String encodedPolicy = new String(Base64.getEncoder().encode(policy_document.getBytes("UTF-8"))).replaceAll("\n", "").replaceAll("\r", "");
    String secretKey = "SiZXM6Qn1M/hNToGUxBBeH+zsTIKYfs+IrDymGLz";

    String signature = getSigning(secretKey, "20151229", "us-east-1", "s3",encodedPolicy);

    System.out.println("base64 " + encodedPolicy);

    System.out.println("signature " + signature);
  }


  static byte[] HmacSHA256(String data, byte[] key) throws Exception
  {
    String algorithm="HmacSHA256";
    Mac mac = Mac.getInstance(algorithm);
    mac.init(new SecretKeySpec(key, algorithm));
    return mac.doFinal(data.getBytes("UTF8"));
  }

  static String getSigning(String key, String dateStamp, String regionName, String serviceName,String base64signature) throws Exception {
    byte[] kSecret = ("AWS4" + key).getBytes("UTF8");
    byte[] kDate = HmacSHA256(dateStamp, kSecret);
    byte[] kRegion = HmacSHA256(regionName, kDate);
    byte[] kService = HmacSHA256(serviceName, kRegion);
    //
    byte[] kSigning = HmacSHA256("aws4_request", kService);

    byte[] signature = HmacSHA256(base64signature, kSigning);

    return new String(Base64.getEncoder().encode(signature));
  }
}
