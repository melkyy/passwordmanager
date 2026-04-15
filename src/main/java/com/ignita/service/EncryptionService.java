package com.ignita.service;

import com.ignita.Main;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Random;

public class EncryptionService {
    private static final Random RANDOM = new SecureRandom();

    public String toHexString(byte[] hash) {
        StringBuilder hashString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hashString.append('0');
            hashString.append(hex);
        }
        return hashString.toString();
    }

    public SecretKey getKeyFromPassword(String password, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, Main.ITERATIONS, Main.KEY_LENGTH);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    public void encryptFile(String password, String filePath, String  jsonPasswordList) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            byte[] iv = new byte[12];

            random.nextBytes(salt);
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, getKeyFromPassword(password, salt), gcmSpec);

            byte[] cipherText = cipher.doFinal(jsonPasswordList.getBytes(StandardCharsets.UTF_8));

            ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();
            outputBuffer.write(salt);
            outputBuffer.write(iv);
            outputBuffer.write(cipherText);

            Files.write(Paths.get(filePath), outputBuffer.toByteArray());

    }
    public byte[] generateSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }


    public String decryptFile(String password, String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] fileData = Files.readAllBytes(Paths.get(filePath));
        ByteBuffer bb = ByteBuffer.wrap(fileData);

        byte[] salt = new byte[16];
        bb.get(salt);

        byte[] iv = new byte[12];
        bb.get(iv);

        byte[] ciphertext = new byte[bb.remaining()];
        bb.get(ciphertext);

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, Main.ITERATIONS, Main.KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

        byte[] decryptedBytes = cipher.doFinal(ciphertext);

        return new String(decryptedBytes, StandardCharsets.UTF_8);

    }

}
