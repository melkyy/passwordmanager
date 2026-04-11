package com.ignita.repository;

import com.ignita.Main;
import com.ignita.model.PasswordModel;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordRepository {

    String filePath = "src/main/resources/db.txt";
    private JSONArray passwordList = null;

    public void setPasswordList(JSONArray passwordList) {
        this.passwordList = passwordList;
    }

    public JSONArray getPasswordList() {
        return passwordList;
    }

    public String generateFile(byte[] passwordHashed, String password, byte[] saltHashed) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        File file = new File(filePath);
        if (file.createNewFile()) {
            System.out.println("Generating DB File");
            String jsonFile = "[]";
            System.out.println("Encrypting File...");
            this.encryptFile(jsonFile, password);
            System.out.println("File Encrypted!!");
            return "[]";
        } else {
            PasswordModel passWordModel = new PasswordModel();
            System.out.println("Getting File Encrypted...");
            Scanner Reader = new Scanner(file);
            StringBuilder fileResult = new StringBuilder();
            while (Reader.hasNextLine()) {
                String data = Reader.nextLine();
                fileResult.append(data);
            }
            System.out.println("File content: " + fileResult);
            System.out.println("Decrypting File...");
            String jsonDecrypted = decryptFile(password);
            System.out.println("JSON: " + jsonDecrypted);
            return jsonDecrypted;
        }
    }

    public void encryptFile(String jsonString, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        EncryptionRepository er = new EncryptionRepository();
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        byte[] iv = new byte[12];

        random.nextBytes(salt);
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, er.getKeyFromPassword(password, salt), gcmSpec);

        byte[] cipherText = cipher.doFinal(jsonString.getBytes(StandardCharsets.UTF_8));

        ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();
        outputBuffer.write(salt);
        outputBuffer.write(iv);
        outputBuffer.write(cipherText);

        Files.write(Paths.get(filePath), outputBuffer.toByteArray());
    }

    public String decryptFile(String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
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


    public PasswordModel[] list() {
        System.out.println("enter into repository");
        if(this.getPasswordList() != null){
            PasswordModel[] pmArray = new PasswordModel[this.passwordList.length()];
            for (int i = 0; i < this.passwordList.length(); i++){
                JSONObject obj = this.passwordList.getJSONObject(i);
                PasswordModel pm = new PasswordModel();
                pm.setName(obj.getString("name"));
                pm.setPassword(obj.getString("password"));
                pmArray[i] = pm;
            }
            return pmArray;
        }else{
            System.out.println("There is not passwords here, create one");
            return null;
        }
    }

    public PasswordModel show(int index) {
        if(this.getPasswordList() != null){
            PasswordModel pm = new PasswordModel();
                JSONObject obj = this.passwordList.getJSONObject(index);
                if(obj != null){
                    pm.setName(obj.getString("name"));
                    pm.setPassword(obj.getString("password"));
                }
            return pm;
        }else{
            System.out.println("Password Not Found");
            return null;
        }
    }

    public void add(String password, String name) {
        JSONObject newPassword =  new JSONObject();
        newPassword.put("password", password);
        newPassword.put("name", name);
        this.passwordList.put(newPassword);
    }

    public void remove(int index) {
        this.passwordList.remove(index);
    }
}
