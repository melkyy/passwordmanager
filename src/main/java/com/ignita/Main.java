package com.ignita;

import com.ignita.model.MasterModel;
import com.ignita.service.PasswordService;
import org.json.JSONArray;

import java.util.Scanner;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static final int ITERATIONS = 50000;
    public static final int KEY_LENGTH = 256;
    public static void main(String[] args) {
        try {

            PasswordService passwordService = new PasswordService();
            MasterModel masterInfo = passwordService.checkMasterFile();
            String password = passwordService.enterPassword(masterInfo);
            if (password.isEmpty()) {
                return;
            }
            String jsonString = passwordService.checkPasswordsFile(password, masterInfo.getPasswordByte());
            JSONArray passwordList = passwordService.convertJSONArray(jsonString);
            passwordService.setPasswordListArray(passwordList);
            String option = "";
            while (!option.equals("0")) {
                System.out.println("1 - add password");
                System.out.println("2- list password");
                System.out.println("3- show password");
                System.out.println("4- remove password");
                System.out.println("0 - exit");

                Scanner s = new Scanner(System.in);
                option = s.nextLine();
                if (option.equals("1")) {
                    Scanner Scan = new Scanner(System.in);
                    System.out.println("enter a name");
                    String nameAdd = Scan.nextLine();
                    System.out.println("enter a password");
                    String passWordAdd = Scan.nextLine();
                    passwordService.add(passWordAdd, nameAdd);
                    System.out.println("ENCRYPTING...");
                    passwordService.encryptFile(password);
                    System.out.println("The file was saved correctly");
                }
                if (option.equals("2")) {
                    passwordService.list();
                }
                if (option.equals("3")) {
                    Scanner Scan = new Scanner(System.in);
                    System.out.println("enter a list of element by number");
                    String index = Scan.nextLine();
                    passwordService.show(Integer.parseInt(index));
                }
                if (option.equals("4")) {
                    Scanner Scan = new Scanner(System.in);
                    System.out.println("enter a list of element by number");
                    String index = Scan.nextLine();
                    passwordService.remove(Integer.parseInt(index));
                    System.out.println("ENCRYPTING...");
                    passwordService.encryptFile(password);
                    System.out.println("The file was saved correctly");
                }
            }
        } catch (Exception e) {
            System.out.println(e);
            System.out.println("OPTION ERROR, INCORRECT OPTION");
        }

    }
}