package com.yang.encryptsample.util;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author admin
 * 在1024的密钥长度下
 * 被加密字符串不能超过117
 * 被解密字符串不能超出128
 * 512的密钥长度下，被加密不能超过53
 */
public class EncryptUtil {
    /**
     * 指定加密算法为RSA
     */
    private static final String ALGORITHM = "RSA";
    /**
     * 密钥长度，用来初始化
     */
    private static final int KEY_SIZE = 1024;
//    private static final int KEY_SIZE = 512;

    /**
     * 生成密钥对
     * Key publicKey = keyPair.getPublic();
     * Key privateKey = keyPair.getPrivate();
     *
     * @return [publicKeyStr, privateKeyStr]
     * @throws Exception
     */
    private static String[] generateKeyPair() throws NoSuchAlgorithmException {

        // /** RSA算法要求有一个可信任的随机数源 */
        SecureRandom secureRandom = new SecureRandom();

        /** 为RSA算法创建一个KeyPairGenerator对象 */
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);

        /** 利用上面的随机数据源初始化这个KeyPairGenerator对象 */
        keyPairGenerator.initialize(KEY_SIZE, secureRandom);

        /** 生成密匙对 */
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        /** 得到公钥 */
        Key publicKey = keyPair.getPublic();

        /** 得到私钥 */
        Key privateKey = keyPair.getPrivate();

        return new String[]{
                Base64.encodeBase64String(publicKey.getEncoded()),
                Base64.encodeBase64String(privateKey.getEncoded())
        };
    }

    /**
     * 公钥加密方法
     *
     * @param source       源数据
     * @param publicKeyStr 公钥字符串
     * @return
     * @throws Exception
     */
    public static String encryptPublic(String source, String publicKeyStr) throws Exception {
        Key publicKey = strToPublicKey(publicKeyStr);

        /** 得到Cipher对象来实现对源数据的RSA加密 */
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] sourceBytes = source.getBytes();
        /** 执行加密操作 */
        byte[] resultBytes = cipher.doFinal(sourceBytes);

        return Base64.encodeBase64String(resultBytes);
    }


    /**
     * 私钥加密方法
     *
     * @param source        源数据
     * @param privateKeyStr 私钥字符串
     * @return
     * @throws Exception
     */
    public static String encryptPrivate(String source, String privateKeyStr) throws Exception {
        Key privateKey = strToPrivateKey(privateKeyStr);

        /** 得到Cipher对象来实现对源数据的RSA加密 */
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] sourceBytes = source.getBytes();
        /** 执行加密操作 */
        byte[] resultBytes = cipher.doFinal(sourceBytes);
        return Base64.encodeBase64String(resultBytes);
    }


    /**
     * 公钥解密算法
     *
     * @param cryptoGraph  密文
     * @param publicKeyStr 公钥字符串
     * @return
     * @throws Exception
     */
    public static String decryptPublic(String cryptoGraph, String publicKeyStr) throws Exception {
        Key publicKey = strToPublicKey(publicKeyStr);

        /** 得到Cipher对象对已用公钥加密的数据进行RSA解密 */
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] bytes = Base64.decodeBase64(cryptoGraph);

        /** 执行解密操作 */
        byte[] originBytes = cipher.doFinal(bytes);
        return new String(originBytes);
    }

    /**
     * 私钥解密算法
     *
     * @param cryptoGraph   密文
     * @param privateKeyStr 私钥字符串
     * @return
     * @throws Exception
     */
    public static String decryptPrivate(String cryptoGraph, String privateKeyStr) throws Exception {
        Key privateKey = strToPrivateKey(privateKeyStr);

        /** 得到Cipher对象对已用公钥加密的数据进行RSA解密 */
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytes = Base64.decodeBase64(cryptoGraph);

        /** 执行解密操作 */
        byte[] originBytes = cipher.doFinal(bytes);
        return new String(originBytes);
    }

    private static PublicKey strToPublicKey(String publicKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] bytes = Base64.decodeBase64(publicKeyStr);
        KeySpec keySpec = new X509EncodedKeySpec(bytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(keySpec);
    }

    private static PrivateKey strToPrivateKey(String privateKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] bytes = Base64.decodeBase64(privateKeyStr);
        KeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(keySpec);
    }

    public static void main(String[] args) throws Exception {
        String[] pairs = generateKeyPair();
        String publicKeyStr = pairs[0];
        String privateKeyStr = pairs[1];
        System.out.println(publicKeyStr);
        System.out.println(privateKeyStr);

        String info = "需要公钥加密，私钥解密";

        String enStr = encryptPublic(info, publicKeyStr);

        System.out.println(enStr);

        System.out.println(decryptPrivate(enStr, privateKeyStr));
        System.out.println("--------");
        String info2 = "需要私钥加密，公钥解密";

        String enStr2 = encryptPrivate(info2, privateKeyStr);

        System.out.println(enStr2);

        System.out.println(decryptPublic(enStr2, publicKeyStr));

    }
}
