package com.ignita.repository;

import com.ignita.model.MasterModel;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Properties;

public class MasterPasswordRepository {
    private String toHexString(byte[] hash) {
        StringBuilder hashString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hashString.append('0');
            hashString.append(hex);
        }
        return hashString.toString();
    }

    public MasterModel setMasterPasswordFile(String newPassword, byte[] salt, int iteration, int keyLength) {
        Properties props = new Properties();
        MasterModel masterInfo = new MasterModel();
        try (InputStream input = this.getClass().getResourceAsStream("/config.properties")) {
            props.load(input);

            PBEKeySpec spec = new PBEKeySpec(newPassword.toCharArray(), salt, iteration, keyLength);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hashedPassword = factory.generateSecret(spec).getEncoded();

            props.setProperty("salt", toHexString(salt));
            props.setProperty("password", toHexString(hashedPassword));
            masterInfo.setPasswordByte(hashedPassword);
            masterInfo.setSaltByte(salt);
            try (OutputStream output = new FileOutputStream(Objects.requireNonNull(this.getClass().getResource("/config.properties")).getPath())) {
                props.store(output, "Application Configuration");
                return masterInfo;
            } catch (NullPointerException e) {
                System.out.println("Exception in getMasterProperties" + e);
            }
        } catch (IOException e) {
            System.out.println("Exception in getMasterProperties: " + e);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return null;
    }


    public MasterModel getMasterPasswordFile() {
        Properties props = new Properties();
        MasterModel masterInfo = new MasterModel();

        try (InputStream input = this.getClass().getResourceAsStream("/config.properties")) {
            props.load(input);
        } catch (IOException e) {
            System.out.println("Exception in getMasterProperties: " + e);
        }

        String storedPassword = props.getProperty("password");
        String storedSalt = props.getProperty("salt");
        if (storedPassword == null || storedSalt == null) {
            return null;
        }
        masterInfo.setPasswordByte(HexFormat.of().parseHex(storedPassword));
        masterInfo.setSaltByte(HexFormat.of().parseHex(storedSalt));
        return masterInfo;
    }

}
