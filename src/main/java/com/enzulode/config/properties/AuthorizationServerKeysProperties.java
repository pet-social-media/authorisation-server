package com.enzulode.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;


@ConfigurationProperties(prefix = "keys")
public class AuthorizationServerKeysProperties {

    public static class RsaKeyPair {
        public RSAPublicKey publicKey;
        public RSAPrivateKey privateKey;

        public void setPublicKey(RSAPublicKey publicKey) {
            this.publicKey = publicKey;
        }
        public RSAPublicKey getPublicKey() {
            return publicKey;
        }

        public void setPrivateKey(RSAPrivateKey privateKey) {
            this.privateKey = privateKey;
        }
        public RSAPrivateKey getPrivateKey() {
            return privateKey;
        }
    }

    @NestedConfigurationProperty
    private List<RsaKeyPair> rsa = new ArrayList<>();

    public List<RsaKeyPair> getRsa() {
        return this.rsa;
    }

    public void setRsa(final List<RsaKeyPair> pairs) {
        this.rsa = pairs;
    }
}
