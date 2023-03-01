package com.coderwlj.jjwt.utils;/**
 * @Classname EsJwtUtil
 * @Description 使用非对称算法生成和解析Token
 * @Date 3/1/2023 6:06 PM
 * @author coderwlj
 */

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.KeyPair;

/**
 * @author: coderwlj
 * @create: 2023-03-01
 */
public class EsJwtUtil {

    private static KeyPair keyPair;

    public static  void keyPairGenerator() {
        /**
         * 非对称加密  明文 + 公钥 + 算法 = 密文 ||  密文 + 私钥 + 算法 = 明文
         */
        keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);
        //keyPair.getPrivate()  获取私钥
        //keyPair.getPublic()   获取公钥
    }

    public static String generateJws() {
        return Jwts.builder()
                // 私钥加密
                .signWith(keyPair.getPrivate())
                .setSubject("coderwlj")
                .compact();
    }

    public static boolean parseJws(String jws) {

        boolean res = false;
        try {
            res = Jwts.parserBuilder()
                    .setSigningKey(keyPair.getPublic())
                    .build()
                    .parseClaimsJws(jws)
                    .getBody()
                    .getSubject()
                    .equals("coderwlj");
        }catch (Exception e) {
            e.printStackTrace();
        }

        return res;
    }


    public static void main(String[] args) {
        keyPairGenerator();
        System.out.println(keyPair.getPublic());
        System.out.println(keyPair.getPrivate());

        System.out.println(generateJws());

        System.out.println(parseJws(generateJws()));
    }

}
