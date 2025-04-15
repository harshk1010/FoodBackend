package com.hk.service;

import com.hk.config.JwtConstant;
import com.hk.config.JwtProvider;
import com.hk.model.User;
import com.hk.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;



@Service

public class UserServiceImp implements UserService{

    @Autowired
     UserRepository userRepository;

    @Autowired
    private JwtProvider jwtProvider;

    @Override
    public User findUserByJwtToken(String jwt) throws Exception {

//        String email = jwtProvider.getEmailFromJwtToken(jwt);
//        User user = findUserByEmail(email);
//
//        return user;
        SecretKey key = Keys.hmacShaKeyFor(JwtConstant.SECRET_KEY.getBytes());
        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt.substring(7)).getBody();

        String email = claims.get("email", String.class);
        if (email == null || email.isEmpty()) {
            throw new Exception("Email not found in token");
        }

        return findUserByEmail(email);
    }

    @Override
    public User findUserByEmail(String email) throws Exception {

        User user = userRepository.findByEmail(email.toLowerCase());
       // log.info("Searching for user with email: {}", email);
        if(user==null) {
            throw new Exception("User not found");
        }

        return user;

    }
}


