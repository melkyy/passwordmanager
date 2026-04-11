package com.ignita.repository;

import com.ignita.Main;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Random;

public class EncryptionRepository {
    private static final Random RANDOM = new SecureRandom();

    public byte[] generateSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }


    public GCMParameterSpec generateIV() throws NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
        return new GCMParameterSpec(128, iv);
    }

    public SecretKey getKeyFromPassword(String password, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, Main.ITERATIONS, Main.KEY_LENGTH);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }


    public byte[] encrypt(byte[] passwordListHash, char[] masterPassword, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PBEKeySpec spec = new PBEKeySpec(masterPassword, salt, Main.ITERATIONS, Main.KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] tmp = factory.generateSecret(spec).getEncoded();
        SecretKey secretKey = new SecretKeySpec(tmp, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        byte[] cipherText = cipher.doFinal(passwordListHash);
        return ByteBuffer.allocate(iv.length + cipherText.length).put(iv).put(cipherText).array();

    }

    public byte[] decrypt(byte[] encryptedDataWithIv, char[] masterPassword, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedDataWithIv);

        byte[] iv = new byte[12];
        byteBuffer.get(iv);

        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        PBEKeySpec spec = new PBEKeySpec(masterPassword, salt, Main.ITERATIONS, Main.KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] tmp = factory.generateSecret(spec).getEncoded();
        SecretKey secretKey = new SecretKeySpec(tmp, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        return cipher.doFinal(cipherText);
    }
}
