package com.coderwlj.jjwt.utils;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

import org.apache.commons.lang3.StringUtils;

/**
 * @author coderwlj
 */
public class RsaUtils {

    /**
     * Rsa2048 公钥
     */
    private final static String RSA_2048_PUB_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC31wT9eT3jgUtIdtIV2bSMniolsfacvlVmoMX2NkL1h//sLvMTKbdFhTVhup0t47vbtnFYkUFGI0Q+ZM/IaUcvDXVaFf5G5GXity1KmbOf3G9+/LkEzty1nzkCRQTM+pZdgl1hIxBxncc4+okYxWKAuFUvgw0xjvuoh5mEqT9/9QIDAQAB";
    /**
     * Rsa2048 私钥
     */
    private final static String RSA_2048_PRI_KEY = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALfXBP15PeOBS0h20hXZtIyeKiWx9py+VWagxfY2QvWH/+wu8xMpt0WFNWG6nS3ju9u2cViRQUYjRD5kz8hpRy8NdVoV/kbkZeK3LUqZs5/cb378uQTO3LWfOQJFBMz6ll2CXWEjEHGdxzj6iRjFYoC4VS+DDTGO+6iHmYSpP3/1AgMBAAECgYB94VqGYZ1yCZdOACZsVczeOHLtqsUNoPqDMnU62P7SdxRTWfaRWZAnp0XdLFXyFS0ODgfguF10tDNHceog9Y2KS3fHJK3JIur1Y55BqKzLlQlrAWpziaigEw+xJqiO+U67gomlCLTS6kYhFvPGXip3wOctvEh8yG1RX3exTmiVwQJBAPlWm6Aok86vHsBS8Znev1VV9nsSexrJXXkkdHv2ux2JSwQi/WNwWloolUtHFCGcyVmhNEmB7sSbR7/hmaKhiNECQQC8wGySaQIessawFnN/i+xmdoO0OeLCaR9MEce3B5dfRlTq37cfCbGCGnhSi5iRzx4/PHJGNoLPP2xFTVZ5VY3lAkA2rsTgwiVwbb2bxlUQPubNa1XsNehjvofOeq1FRp5Q4vxdwuK5fTmDjmT3pnYGzSDnlFAoUuOvoLKCpZKRNUYRAkALj4WW2hOlKbH9qwJb94f9JpkeesUmvyWJlTU0QqTE0xv0XstqfT+ABnsEI0Su+Y6StPMS1dfhNbM982Sufcz5AkB8OC1vMSQ0oYKxgS3nvNyNlTEjcveJALQAgU7vpSiA0/5LdwUFb7gCKQDL6pq8ySbZ4NV/U5xDVoBzsa5AIEVK";
    /**
     * 编码格式
     */
    private final static String CHARSET = "UTF-8";
    /**
     * 算法
     */
    private final static String ALGORITHM = "RSA";
    /**
     * 私钥对象
     */
    private static PrivateKey privateKey;

    /**
     * 公钥对象
     */
    private static PublicKey publicKey;

    static {
        try {
            //将Base64 字符串转化为字节数组
            byte[] keyBytes = Base64.decodeBase64(RSA_2048_PRI_KEY.getBytes(CHARSET));
            //私钥标准
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
            //指定算法，比如 RSA
            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
            //获取私钥
            privateKey = factory.generatePrivate(pkcs8EncodedKeySpec);

        } catch (Exception e) {
            privateKey = null;
            //出现异常
        }

        try {
            //将Base64 字符串转化为字节数组
            byte[] keyBytes = Base64.decodeBase64(RSA_2048_PUB_KEY.getBytes(CHARSET));
            //公钥标准
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
            //指定算法 比如 RSA
            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
            //获取公钥
            publicKey = factory.generatePublic(x509EncodedKeySpec);
        } catch (Exception e) {
            publicKey = null;
            //出现异常
        }
    }

    /**
     * 私钥解密
     *
     * @param content
     * @return
     */
    public static String decryptByPriKey(String content) {
        //判断非空
        if (StringUtils.isBlank(content) || privateKey == null) {
            return "";
        }
        try {
            //进行解密处理
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            content = new String(cipher.doFinal(Base64.decodeBase64(content.getBytes(CHARSET))));
        } catch (Exception e) {
            content = "";
        }

        return content;
    }

    /**
     * 私钥加密
     */
    public static String encryptByPriKey(String content) {

        //判断非空
        if (StringUtils.isBlank(content) || privateKey == null) {
            return "";
        }
        try {
            //进行加密处理
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            content = Base64.encodeBase64String(cipher.doFinal(content.getBytes(CHARSET)));
        } catch (Exception e) {
            content = "";
        }

        return content;
    }

    /**
     * 公钥解密
     *
     * @param content
     * @return
     */
    public static String decryptByPubKey(String content) {
        //判断非空
        if (StringUtils.isBlank(content) || publicKey == null) {
            return "";
        }
        try {
            //进行解密处理
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            content = new String(cipher.doFinal(Base64.decodeBase64(content.getBytes(CHARSET))));
        } catch (Exception e) {
            content = "";
        }

        return content;
    }

    /**
     * 公钥加密
     */
    public static String encryptByPubKey(String content) {

        //判断非空
        if (StringUtils.isBlank(content) || publicKey == null) {
            return "";
        }
        try {
            //进行加密处理
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            content = Base64.encodeBase64String(cipher.doFinal(content.getBytes(CHARSET)));
        } catch (Exception e) {
            content = "";
        }

        return content;
    }

    public static void main(String[] args) {
        String content = "123456";
        System.out.println("内容:" + content);
        String contentEnByPub = "";
        System.out.println("公钥加密:" + (contentEnByPub = RsaUtils.encryptByPubKey(content)));
        System.out.println("私钥解密:" + (content = RsaUtils.decryptByPriKey(contentEnByPub)));

        String content2 = "123456";
        System.out.println("内容2:" + content2);
        String contentEnByPri = "";
        System.out.println("私钥加密:" + (contentEnByPri = RsaUtils.encryptByPriKey(content2)));
        System.out.println("公钥解密:" + (content2 = RsaUtils.decryptByPubKey(contentEnByPri)));
    }


}
