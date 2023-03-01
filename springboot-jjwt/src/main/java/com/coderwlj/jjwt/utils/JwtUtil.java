package com.coderwlj.jjwt.utils;/**
 * @Classname JwtUtil
 * @Description generate jwt
 * @Date 2023/2/27 19:29
 * @author coderwlj
 */
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;

/**
 * @author: coderwlj
 * @create: 2023-02-27
 */
public class JwtUtil {
    private static String keyString ;

    private static SecretKey key;

    public static void keyGen() {

        key  = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        keyString = Encoders.BASE64.encode(Keys.secretKeyFor(SignatureAlgorithm.HS256).getEncoded());
    }

    public static String generateJwtString() {

        String jws = Jwts.builder().setSubject("Joe").signWith(key).compact();

        return jws;
    }



    public static boolean parserJws(String jws) {

        boolean res = false;

        try {
            res = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(jws).getBody().getSubject().equals("Joe");
        } catch (JwtException e) {
            e.printStackTrace();
        }

        return res;

    }
    public static void main(String[] args) {

        keyGen();


        System.out.println(keyString);


        System.out.println(generateJwtString());


        if(parserJws(generateJwtString()))  {
            System.out.println("OK");
        }
        else {
            System.out.println("No");
        }


    }

}
