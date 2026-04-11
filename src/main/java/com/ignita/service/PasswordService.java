package com.ignita.service;

import com.ignita.Main;
import com.ignita.model.MasterModel;
import com.ignita.model.PasswordModel;
import com.ignita.repository.EncryptionRepository;
import com.ignita.repository.MasterPasswordRepository;
import com.ignita.repository.PasswordRepository;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordService {
    PasswordRepository pr;

    public void setPasswordListArray(JSONArray passwordList){
        pr = new PasswordRepository();
        pr.setPasswordList(passwordList);
    }

    public MasterModel checkMasterFile() {
        System.out.println("CHECKING MASTER FILE...");
        EncryptionRepository er = new EncryptionRepository();
        MasterPasswordRepository passwordRepository = new MasterPasswordRepository();
        MasterModel masterInfo = passwordRepository.getMasterPasswordFile();
        Scanner Scan = new Scanner(System.in);

        if (masterInfo == null) {
            System.out.println("Enter a new password: ");
            System.out.println("NOTICE: If you forget the password, it cannot be recovered");
            String newPassword = Scan.nextLine();

            masterInfo = passwordRepository.setMasterPasswordFile(newPassword, er.generateSalt(), Main.ITERATIONS, Main.KEY_LENGTH);
            System.out.println("Password set!!");
        }
        return masterInfo;
    }

    public String checkPasswordsFile(String password, byte[] passwordHased) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        System.out.println("CHECKING PASSWORD LIST FILE...");
        PasswordRepository pr = new PasswordRepository();
        return pr.generateFile(null, password, passwordHased);
    }

    public JSONArray convertJSONArray(String jsonString) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        PasswordRepository pr = new PasswordRepository();
        return new JSONArray(jsonString);
    }

    public String enterPassword(MasterModel masterInfo) throws NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("--- WELCOME! ---");

        Scanner Scan = new Scanner(System.in);

        System.out.println("Enter Password: ");
        String newPassword = Scan.nextLine();
        if (validatePassword(newPassword, masterInfo.getSaltByte(), masterInfo.getPasswordByte())) {
            System.out.println("----- Correct Password ------");
            return newPassword;
        } else {
            System.out.println("----- Incorrect Password ------");
            return "";
        }
    }
    public void encryptFile(String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, InvalidKeySpecException, InvalidKeyException {
        if(pr.getPasswordList() != null){
            String jsonPasswordList = pr.getPasswordList().toString();
            pr.encryptFile(jsonPasswordList, password);
        }

    }

    public static boolean validatePassword(String password, byte[] salt, byte[] storedHash) throws NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("VALIDATING PASSWORD...");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, Main.ITERATIONS, Main.KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
        return Arrays.equals(hashedPassword, storedHash);
    }

    public void list() {
        System.out.println("LISTING...");
        PasswordModel[] pm;
        pm = pr.list();
        if (pm.length == 0) {
            System.out.println("No items in list create one");
            return;
        }
        int index= 1;
        for (PasswordModel passwordModel : pm) {

            System.out.println("-----------------------");
            System.out.println("index: "+ index);
            System.out.println("Name: " + passwordModel.getName());
            System.out.println("Password: " + passwordModel.getPassword().replaceAll(".(?=.*)", "*"));
            System.out.println("-----------------------");
            index++;
        }
    }

    public void add(String password, String name) {
        if (password.isBlank()) {
            System.out.println("Password required");
            return;
        }
        if (name.isBlank()) {
            System.out.println("Name required");
        }
        pr.add(password, name);
        System.out.println("Password added");
        this.list();
    }

    public void show(int index){
        PasswordModel pm = pr.show(index - 1);
        System.out.println("-----------------------");
        System.out.println("index: "+index);
        System.out.println("Name: " + pm.getName());
        System.out.println("Password: "+ pm.getPassword());
        System.out.println("-----------------------");
    }

    public void remove(int index){
         pr.remove(index - 1);
        System.out.println("Password Removed");
    }
}
