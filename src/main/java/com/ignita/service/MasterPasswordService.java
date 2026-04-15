package com.ignita.service;

import com.ignita.Main;
import com.ignita.model.PasswordMasterModel;
import org.json.JSONArray;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class MasterPasswordService {
    private final EncryptionService encryptionService;

    public MasterPasswordService(){
        encryptionService =  new EncryptionService();
    }

    public void createDirectory(){

        File directory = new File(Main.mainDirectory);
        if(!directory.exists()){
            if(directory.mkdir()){
                System.out.println("Password manager directory created at: "+Main.filePathConfig );
            }else{
                System.out.println("Failed to create a directory. check permissions");
            }
        }
    }

    public boolean masterFileExist() throws IOException {
        PasswordMasterModel masterInfo = this.getMasterPasswordFile();
        return masterInfo != null;
    }

    public PasswordMasterModel setMasterPasswordFile(String newPassword, int iteration, int keyLength) {
        Properties props = new Properties();
        PasswordMasterModel masterInfo = new PasswordMasterModel();
        File file = new File(Main.filePathConfig);
        byte[] salt  = encryptionService.generateSalt();
        try (FileInputStream input = new FileInputStream(file)) {
            props.load(input);

            PBEKeySpec spec = new PBEKeySpec(newPassword.toCharArray(), salt, iteration, keyLength);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hashedPassword = factory.generateSecret(spec).getEncoded();

            props.setProperty("salt", encryptionService.toHexString(salt));
            props.setProperty("password", encryptionService.toHexString(hashedPassword));
            masterInfo.setPasswordByte(hashedPassword);
            masterInfo.setSaltByte(salt);
            return masterInfo;
        } catch (IOException e) {
            System.out.println("Exception in getMasterProperties: " + e);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    public String generateFile(String password) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        File file = new File(Main.filePathDB);
        if (file.createNewFile()) {
            String jsonFile = "[]";
            encryptionService.encryptFile(password, Main.filePathDB, jsonFile);
            return "[]";
        } else{
            return encryptionService.decryptFile(password, Main.filePathDB);
        }
    }

    public JSONArray convertJSONArray(String jsonString) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        return new JSONArray(jsonString);
    }

    public boolean validatePassword(String password, byte[] salt, byte[] storedHash) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, Main.ITERATIONS, Main.KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
        return Arrays.equals(hashedPassword, storedHash);
    }

    public PasswordMasterModel getMasterPasswordFile() throws IOException {
        File file = new File(Main.filePathConfig);
        PasswordMasterModel masterInfo = new PasswordMasterModel();
        Properties props = new Properties();
        if(!file.exists()){
            if(!file.createNewFile()) {
            return null;
            }
        }
        try (InputStream input = new FileInputStream(file)) {
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
