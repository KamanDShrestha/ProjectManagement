/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JFrame.java to edit this template
 */
package ProjectManagement;
import java.sql.Statement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import javax.swing.JOptionPane;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

//password encryption
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.table.DefaultTableModel;
/**
 *
 * @author KAMAN
 */
public class ProjectManagement extends javax.swing.JFrame {
    static final String DB_URL = "jdbc:mysql://localhost/project_management";
    static final String PASSWORD = "";
    static final String USER = "root";
    
     private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";

    private static final int TAG_LENGTH_BIT = 128; // must be one of {128, 120, 112, 104, 96}
    private static final int IV_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 16;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

   
     public static byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    // AES secret key
    public static SecretKey getAESKey(int keysize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keysize, SecureRandom.getInstanceStrong());
        return keyGen.generateKey();
    }

    // Password derived AES 256 bits secret key
    public static SecretKey getAESKeyFromPassword(char[] password, byte[] salt)
        
             {

           try {
               SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
               // iterationCount = 65536
               // keyLength = 256
               KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
               SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
               return secret;
           } catch (NoSuchAlgorithmException ex) {
               Logger.getLogger(ProjectManagement.class.getName()).log(Level.SEVERE, null, ex);
           } catch (InvalidKeySpecException ex) {
               Logger.getLogger(ProjectManagement.class.getName()).log(Level.SEVERE, null, ex);
           }
return null;
    }
 

    // return a base64 encoded AES encrypted text
    public static String encrypt(String username, String password) throws Exception {

        // 16 bytes salt
        byte[] salt = getRandomNonce(SALT_LENGTH_BYTE);

        // GCM recommended 12 bytes iv?
        byte[] iv = getRandomNonce(IV_LENGTH_BYTE);

        // secret key from password
        SecretKey aesKeyFromPassword = getAESKeyFromPassword(username.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        // ASE-GCM needs GCMParameterSpec
        cipher.init(Cipher.ENCRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        byte[] cipherText = cipher.doFinal(password.getBytes());

        // prefix IV and Salt to cipher text
        byte[] cipherTextWithIvSalt = ByteBuffer.allocate(iv.length + salt.length + cipherText.length)
                .put(iv)
                .put(salt)
                .put(cipherText)
                .array();

        // string representation, base64, send this string to other for decryption.
        return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);

    }
    private static String decrypt(String username, String encryptedPassword) throws Exception {

        byte[] decode = Base64.getDecoder().decode(encryptedPassword.getBytes(UTF_8));

        // get back the iv and salt from the cipher text
        ByteBuffer bb = ByteBuffer.wrap(decode);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);

        byte[] salt = new byte[SALT_LENGTH_BYTE];
        bb.get(salt);

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        // get back the aes key from the same password and salt
        SecretKey aesKeyFromPassword = getAESKeyFromPassword(username.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        byte[] plainText = cipher.doFinal(cipherText);

        return new String(plainText, UTF_8);

    }

    
    public static Connection setConnection(){
        Connection conn = null;
        try{
        conn= DriverManager.getConnection(DB_URL, USER, PASSWORD);
        } catch(SQLException e){
            System.out.println("Error: " + e.getMessage());
        }
        return conn;
    }
    /**
     * Creates new form ProjectManagement
     */
    public ProjectManagement() {
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        registerPnl = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        userRegisterPnl = new javax.swing.JPanel();
        userRegisterTxtFld = new javax.swing.JTextField();
        passRegisterPnl = new javax.swing.JPanel();
        passRegisterTxtFld = new javax.swing.JTextField();
        emailRegisterPnl = new javax.swing.JPanel();
        emailRegisterTxtFld = new javax.swing.JTextField();
        departRegisterPnl = new javax.swing.JPanel();
        departRegisterTxtFld = new javax.swing.JTextField();
        registerLbl = new javax.swing.JLabel();
        registerProjectLbl = new javax.swing.JLabel();
        projectRegisterPnl = new javax.swing.JPanel();
        projectRegisterTxtFld = new javax.swing.JTextField();
        costRegisterPnl = new javax.swing.JPanel();
        costRegisterTxtFld = new javax.swing.JTextField();
        assignedYearR = new javax.swing.JComboBox<>();
        assignedDateLbl = new javax.swing.JLabel();
        assignedMonthR = new javax.swing.JComboBox<>();
        assignedDayR = new javax.swing.JComboBox<>();
        dueDateLbl = new javax.swing.JLabel();
        dueYearR = new javax.swing.JComboBox<>();
        dueMonthR = new javax.swing.JComboBox<>();
        dueDayR = new javax.swing.JComboBox<>();
        registerBtnR = new javax.swing.JButton();
        backBtn = new javax.swing.JButton();
        mobileRegisterPnl = new javax.swing.JPanel();
        mobileRegisterTxtFld = new javax.swing.JTextField();
        mainPnl = new javax.swing.JPanel();
        jPanel2 = new javax.swing.JPanel();
        mainScreenLbl = new java.awt.Label();
        logOutBtn = new javax.swing.JButton();
        mainTabbedPane = new javax.swing.JTabbedPane();
        homePage = new javax.swing.JPanel();
        jScrollBar1 = new javax.swing.JScrollBar();
        projectsPage = new javax.swing.JPanel();
        toDoPnl = new javax.swing.JPanel();
        toDoLbl = new javax.swing.JLabel();
        toDoPane = new javax.swing.JScrollPane();
        toDoTbl = new javax.swing.JTable();
        donePnl = new javax.swing.JPanel();
        doneLbl = new javax.swing.JLabel();
        donePane = new javax.swing.JScrollPane();
        doneTbl = new javax.swing.JTable();
        doingPnl = new javax.swing.JPanel();
        doingLbl = new javax.swing.JLabel();
        doingPane = new javax.swing.JScrollPane();
        doingTbl = new javax.swing.JTable();
        usersPage = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        usersInfoTbl = new javax.swing.JTable();
        jLabel3 = new javax.swing.JLabel();
        profilePage = new javax.swing.JPanel();
        editProjects = new javax.swing.JPanel();
        forgetPassPnl = new javax.swing.JPanel();
        forgetPassLbl = new javax.swing.JLabel();
        forgetInfoPnl = new javax.swing.JLabel();
        userForgetPnl = new javax.swing.JPanel();
        userForgetTxtFld = new javax.swing.JTextField();
        emailForgetPnl = new javax.swing.JPanel();
        emailForgetTxtFld = new javax.swing.JTextField();
        passRForgetPnl = new javax.swing.JPanel();
        passRForgetTxtFld = new javax.swing.JTextField();
        passForgetPnl = new javax.swing.JPanel();
        passForgetTxtFld = new javax.swing.JTextField();
        submitBtn = new javax.swing.JButton();
        backForgetBtn = new javax.swing.JButton();
        logInPnl = new javax.swing.JPanel();
        jPanel1 = new javax.swing.JPanel();
        logoP = new javax.swing.JLabel();
        logoLbl = new javax.swing.JLabel();
        logInLbl = new javax.swing.JLabel();
        userNamePnl = new javax.swing.JPanel();
        userLogInTxtFld = new javax.swing.JTextField();
        passPnl = new javax.swing.JPanel();
        passLogInTxtFld = new javax.swing.JTextField();
        logInBtn = new javax.swing.JButton();
        forgetPasswordRadio = new javax.swing.JRadioButton();
        registerBtn = new javax.swing.JButton();
        logo = new javax.swing.JLabel();

        registerPnl.setMaximumSize(new java.awt.Dimension(1365, 775));
        registerPnl.setPreferredSize(new java.awt.Dimension(1365, 775));

        jLabel1.setFont(new java.awt.Font("Segoe UI", 1, 48)); // NOI18N
        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel1.setText("Register");

        jLabel2.setFont(new java.awt.Font("Segoe UI", 2, 14)); // NOI18N
        jLabel2.setText("*Please provide valid information for registering your projects.");

        userRegisterPnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "User Name", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        userRegisterTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                userRegisterTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout userRegisterPnlLayout = new javax.swing.GroupLayout(userRegisterPnl);
        userRegisterPnl.setLayout(userRegisterPnlLayout);
        userRegisterPnlLayout.setHorizontalGroup(
            userRegisterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, userRegisterPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(userRegisterTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 299, Short.MAX_VALUE)
                .addContainerGap())
        );
        userRegisterPnlLayout.setVerticalGroup(
            userRegisterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(userRegisterPnlLayout.createSequentialGroup()
                .addComponent(userRegisterTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 47, Short.MAX_VALUE)
                .addContainerGap())
        );

        passRegisterPnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Password", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        passRegisterTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                passRegisterTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout passRegisterPnlLayout = new javax.swing.GroupLayout(passRegisterPnl);
        passRegisterPnl.setLayout(passRegisterPnlLayout);
        passRegisterPnlLayout.setHorizontalGroup(
            passRegisterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, passRegisterPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(passRegisterTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 279, Short.MAX_VALUE)
                .addContainerGap())
        );
        passRegisterPnlLayout.setVerticalGroup(
            passRegisterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passRegisterPnlLayout.createSequentialGroup()
                .addComponent(passRegisterTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 47, Short.MAX_VALUE)
                .addContainerGap())
        );

        emailRegisterPnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Email Address", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        emailRegisterTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                emailRegisterTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout emailRegisterPnlLayout = new javax.swing.GroupLayout(emailRegisterPnl);
        emailRegisterPnl.setLayout(emailRegisterPnlLayout);
        emailRegisterPnlLayout.setHorizontalGroup(
            emailRegisterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(emailRegisterPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(emailRegisterTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 299, Short.MAX_VALUE)
                .addContainerGap())
        );
        emailRegisterPnlLayout.setVerticalGroup(
            emailRegisterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(emailRegisterPnlLayout.createSequentialGroup()
                .addComponent(emailRegisterTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 56, Short.MAX_VALUE)
                .addContainerGap())
        );

        departRegisterPnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Department Name", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        departRegisterTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                departRegisterTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout departRegisterPnlLayout = new javax.swing.GroupLayout(departRegisterPnl);
        departRegisterPnl.setLayout(departRegisterPnlLayout);
        departRegisterPnlLayout.setHorizontalGroup(
            departRegisterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, departRegisterPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(departRegisterTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 279, Short.MAX_VALUE)
                .addContainerGap())
        );
        departRegisterPnlLayout.setVerticalGroup(
            departRegisterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(departRegisterPnlLayout.createSequentialGroup()
                .addComponent(departRegisterTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 56, Short.MAX_VALUE)
                .addContainerGap())
        );

        registerLbl.setFont(new java.awt.Font("Segoe UI Semibold", 1, 18)); // NOI18N
        registerLbl.setText("Personal Details");

        registerProjectLbl.setFont(new java.awt.Font("Segoe UI Semibold", 1, 18)); // NOI18N
        registerProjectLbl.setText("Project Details");

        projectRegisterPnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Project Name", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        projectRegisterTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                projectRegisterTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout projectRegisterPnlLayout = new javax.swing.GroupLayout(projectRegisterPnl);
        projectRegisterPnl.setLayout(projectRegisterPnlLayout);
        projectRegisterPnlLayout.setHorizontalGroup(
            projectRegisterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(projectRegisterPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(projectRegisterTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 299, Short.MAX_VALUE)
                .addContainerGap())
        );
        projectRegisterPnlLayout.setVerticalGroup(
            projectRegisterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(projectRegisterPnlLayout.createSequentialGroup()
                .addComponent(projectRegisterTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 56, Short.MAX_VALUE)
                .addContainerGap())
        );

        costRegisterPnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Cost/Expense Estimation\n", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        costRegisterTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                costRegisterTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout costRegisterPnlLayout = new javax.swing.GroupLayout(costRegisterPnl);
        costRegisterPnl.setLayout(costRegisterPnlLayout);
        costRegisterPnlLayout.setHorizontalGroup(
            costRegisterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(costRegisterPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(costRegisterTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 299, Short.MAX_VALUE)
                .addContainerGap())
        );
        costRegisterPnlLayout.setVerticalGroup(
            costRegisterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(costRegisterPnlLayout.createSequentialGroup()
                .addComponent(costRegisterTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 56, Short.MAX_VALUE)
                .addContainerGap())
        );

        assignedYearR.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        assignedYearR.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026", " " }));
        assignedYearR.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                assignedYearRActionPerformed(evt);
            }
        });

        assignedDateLbl.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        assignedDateLbl.setText("Assigned Date");

        assignedMonthR.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        assignedMonthR.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", " " }));
        assignedMonthR.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                assignedMonthRActionPerformed(evt);
            }
        });

        assignedDayR.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        assignedDayR.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", " ", " " }));
        assignedDayR.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                assignedDayRActionPerformed(evt);
            }
        });

        dueDateLbl.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        dueDateLbl.setText("Due Date");

        dueYearR.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        dueYearR.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026", " " }));
        dueYearR.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dueYearRActionPerformed(evt);
            }
        });

        dueMonthR.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        dueMonthR.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", " " }));
        dueMonthR.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dueMonthRActionPerformed(evt);
            }
        });

        dueDayR.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        dueDayR.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", " ", " " }));
        dueDayR.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dueDayRActionPerformed(evt);
            }
        });

        registerBtnR.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        registerBtnR.setText("Register");
        registerBtnR.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                registerBtnRActionPerformed(evt);
            }
        });

        backBtn.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        backBtn.setText("Back");
        backBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                backBtnActionPerformed(evt);
            }
        });

        mobileRegisterPnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Mobile Number", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        mobileRegisterTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mobileRegisterTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout mobileRegisterPnlLayout = new javax.swing.GroupLayout(mobileRegisterPnl);
        mobileRegisterPnl.setLayout(mobileRegisterPnlLayout);
        mobileRegisterPnlLayout.setHorizontalGroup(
            mobileRegisterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mobileRegisterPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(mobileRegisterTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 189, Short.MAX_VALUE)
                .addContainerGap())
        );
        mobileRegisterPnlLayout.setVerticalGroup(
            mobileRegisterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mobileRegisterPnlLayout.createSequentialGroup()
                .addComponent(mobileRegisterTxtFld, javax.swing.GroupLayout.PREFERRED_SIZE, 46, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 6, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout registerPnlLayout = new javax.swing.GroupLayout(registerPnl);
        registerPnl.setLayout(registerPnlLayout);
        registerPnlLayout.setHorizontalGroup(
            registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(registerPnlLayout.createSequentialGroup()
                .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(registerPnlLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, 1353, Short.MAX_VALUE))
                    .addGroup(registerPnlLayout.createSequentialGroup()
                        .addGap(281, 281, 281)
                        .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(registerPnlLayout.createSequentialGroup()
                                .addGap(6, 6, 6)
                                .addComponent(registerProjectLbl))
                            .addGroup(registerPnlLayout.createSequentialGroup()
                                .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(userRegisterPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(projectRegisterPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(emailRegisterPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(6, 6, 6)
                                .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(costRegisterPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addGroup(registerPnlLayout.createSequentialGroup()
                                        .addComponent(mobileRegisterPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addComponent(passRegisterPnl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(departRegisterPnl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))))))
                        .addGap(0, 233, Short.MAX_VALUE)))
                .addContainerGap())
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, registerPnlLayout.createSequentialGroup()
                .addGap(0, 0, Short.MAX_VALUE)
                .addComponent(assignedDateLbl)
                .addGap(633, 633, 633))
            .addGroup(registerPnlLayout.createSequentialGroup()
                .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(registerPnlLayout.createSequentialGroup()
                        .addGap(551, 551, 551)
                        .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(registerPnlLayout.createSequentialGroup()
                                .addComponent(assignedYearR, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(assignedMonthR, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(assignedDayR, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(registerPnlLayout.createSequentialGroup()
                                .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(dueDateLbl)
                                    .addGroup(registerPnlLayout.createSequentialGroup()
                                        .addComponent(dueYearR, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(18, 18, 18)
                                        .addComponent(dueMonthR, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                                .addGap(18, 18, 18)
                                .addComponent(dueDayR, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGap(91, 91, 91)
                        .addComponent(registerBtnR, javax.swing.GroupLayout.PREFERRED_SIZE, 118, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(39, 39, 39)
                        .addComponent(backBtn))
                    .addGroup(registerPnlLayout.createSequentialGroup()
                        .addGap(476, 476, 476)
                        .addComponent(jLabel2))
                    .addGroup(registerPnlLayout.createSequentialGroup()
                        .addGap(291, 291, 291)
                        .addComponent(registerLbl)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        registerPnlLayout.setVerticalGroup(
            registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(registerPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel2)
                .addGap(13, 13, 13)
                .addComponent(registerLbl)
                .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(registerPnlLayout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(userRegisterPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(passRegisterPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(18, 18, 18)
                        .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(departRegisterPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(emailRegisterPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(registerPnlLayout.createSequentialGroup()
                        .addGap(73, 73, 73)
                        .addComponent(mobileRegisterPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(registerProjectLbl)
                .addGap(18, 18, 18)
                .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(projectRegisterPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(costRegisterPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(10, 10, 10)
                .addComponent(assignedDateLbl)
                .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(registerPnlLayout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(assignedYearR, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(assignedMonthR, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(assignedDayR, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(18, 18, 18)
                        .addComponent(dueDateLbl))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, registerPnlLayout.createSequentialGroup()
                        .addGap(26, 26, 26)
                        .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(registerBtnR, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(backBtn))))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(registerPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(dueYearR, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(dueMonthR, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(dueDayR, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(174, Short.MAX_VALUE))
        );

        mainPnl.setPreferredSize(new java.awt.Dimension(1365, 775));

        jPanel2.setBackground(new java.awt.Color(214, 214, 221));

        mainScreenLbl.setAlignment(java.awt.Label.CENTER);
        mainScreenLbl.setFont(new java.awt.Font("Dialog", 1, 18)); // NOI18N
        mainScreenLbl.setForeground(new java.awt.Color(51, 51, 51));
        mainScreenLbl.setText("Project Manager/Viewer");

        logOutBtn.setBackground(new java.awt.Color(51, 51, 51));
        logOutBtn.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        logOutBtn.setForeground(new java.awt.Color(204, 204, 204));
        logOutBtn.setText("Log Out");
        logOutBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                logOutBtnActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGap(90, 90, 90)
                .addComponent(mainScreenLbl, javax.swing.GroupLayout.PREFERRED_SIZE, 1163, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(logOutBtn)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGap(21, 21, 21)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(mainScreenLbl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(logOutBtn))
                .addContainerGap(15, Short.MAX_VALUE))
        );

        mainTabbedPane.setBackground(new java.awt.Color(153, 153, 153));
        mainTabbedPane.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                mainTabbedPaneStateChanged(evt);
            }
        });

        jScrollBar1.addMouseWheelListener(new java.awt.event.MouseWheelListener() {
            public void mouseWheelMoved(java.awt.event.MouseWheelEvent evt) {
                jScrollBar1MouseWheelMoved(evt);
            }
        });

        javax.swing.GroupLayout homePageLayout = new javax.swing.GroupLayout(homePage);
        homePage.setLayout(homePageLayout);
        homePageLayout.setHorizontalGroup(
            homePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, homePageLayout.createSequentialGroup()
                .addContainerGap(1357, Short.MAX_VALUE)
                .addComponent(jScrollBar1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );
        homePageLayout.setVerticalGroup(
            homePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollBar1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        mainTabbedPane.addTab("Home", homePage);

        toDoLbl.setFont(new java.awt.Font("Segoe UI", 1, 36)); // NOI18N
        toDoLbl.setText("To Do");

        toDoTbl.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Project Name", "Team Lead", "Assigned Date", "Due Date"
            }
        ) {
            boolean[] canEdit = new boolean [] {
                false, false, false, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        toDoPane.setViewportView(toDoTbl);

        javax.swing.GroupLayout toDoPnlLayout = new javax.swing.GroupLayout(toDoPnl);
        toDoPnl.setLayout(toDoPnlLayout);
        toDoPnlLayout.setHorizontalGroup(
            toDoPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(toDoPnlLayout.createSequentialGroup()
                .addGroup(toDoPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(toDoPnlLayout.createSequentialGroup()
                        .addGap(44, 44, 44)
                        .addComponent(toDoLbl))
                    .addGroup(toDoPnlLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(toDoPane, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        toDoPnlLayout.setVerticalGroup(
            toDoPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(toDoPnlLayout.createSequentialGroup()
                .addGap(15, 15, 15)
                .addComponent(toDoLbl)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(toDoPane, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        doneLbl.setFont(new java.awt.Font("Segoe UI", 1, 36)); // NOI18N
        doneLbl.setText("Done");

        doneTbl.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null},
                {null, null, null},
                {null, null, null},
                {null, null, null}
            },
            new String [] {
                "Project Name", "Team Lead", "Completion Date"
            }
        ));
        donePane.setViewportView(doneTbl);

        javax.swing.GroupLayout donePnlLayout = new javax.swing.GroupLayout(donePnl);
        donePnl.setLayout(donePnlLayout);
        donePnlLayout.setHorizontalGroup(
            donePnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(donePnlLayout.createSequentialGroup()
                .addGap(44, 44, 44)
                .addComponent(doneLbl)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(donePnlLayout.createSequentialGroup()
                .addComponent(donePane, javax.swing.GroupLayout.PREFERRED_SIZE, 433, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 19, Short.MAX_VALUE))
        );
        donePnlLayout.setVerticalGroup(
            donePnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(donePnlLayout.createSequentialGroup()
                .addGap(15, 15, 15)
                .addComponent(doneLbl)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(donePane, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(18, Short.MAX_VALUE))
        );

        doingLbl.setFont(new java.awt.Font("Segoe UI", 1, 36)); // NOI18N
        doingLbl.setText("Doing");

        doingTbl.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Project Name", "Team Lead", "Assigned Date", "Due Date"
            }
        ));
        doingPane.setViewportView(doingTbl);

        javax.swing.GroupLayout doingPnlLayout = new javax.swing.GroupLayout(doingPnl);
        doingPnl.setLayout(doingPnlLayout);
        doingPnlLayout.setHorizontalGroup(
            doingPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(doingPnlLayout.createSequentialGroup()
                .addGroup(doingPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(doingPnlLayout.createSequentialGroup()
                        .addGap(44, 44, 44)
                        .addComponent(doingLbl))
                    .addGroup(doingPnlLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(doingPane, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        doingPnlLayout.setVerticalGroup(
            doingPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(doingPnlLayout.createSequentialGroup()
                .addGap(15, 15, 15)
                .addComponent(doingLbl)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(doingPane, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        javax.swing.GroupLayout projectsPageLayout = new javax.swing.GroupLayout(projectsPage);
        projectsPage.setLayout(projectsPageLayout);
        projectsPageLayout.setHorizontalGroup(
            projectsPageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(projectsPageLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(toDoPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(doingPnl, javax.swing.GroupLayout.PREFERRED_SIZE, 452, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(donePnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        projectsPageLayout.setVerticalGroup(
            projectsPageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, projectsPageLayout.createSequentialGroup()
                .addContainerGap(87, Short.MAX_VALUE)
                .addGroup(projectsPageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(toDoPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(doingPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(donePnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(62, 62, 62))
        );

        mainTabbedPane.addTab("View Projects", projectsPage);

        usersInfoTbl.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "User Name", "Email", "Department", "Mobile Number"
            }
        ) {
            boolean[] canEdit = new boolean [] {
                false, false, true, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        jScrollPane1.setViewportView(usersInfoTbl);

        jLabel3.setFont(new java.awt.Font("Segoe UI", 1, 24)); // NOI18N
        jLabel3.setText("Users' info");

        javax.swing.GroupLayout usersPageLayout = new javax.swing.GroupLayout(usersPage);
        usersPage.setLayout(usersPageLayout);
        usersPageLayout.setHorizontalGroup(
            usersPageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(usersPageLayout.createSequentialGroup()
                .addGap(88, 88, 88)
                .addComponent(jLabel3)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, usersPageLayout.createSequentialGroup()
                .addContainerGap(39, Short.MAX_VALUE)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 1310, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18))
        );
        usersPageLayout.setVerticalGroup(
            usersPageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(usersPageLayout.createSequentialGroup()
                .addGap(15, 15, 15)
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(183, Short.MAX_VALUE))
        );

        mainTabbedPane.addTab("User Information", usersPage);

        javax.swing.GroupLayout profilePageLayout = new javax.swing.GroupLayout(profilePage);
        profilePage.setLayout(profilePageLayout);
        profilePageLayout.setHorizontalGroup(
            profilePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 1367, Short.MAX_VALUE)
        );
        profilePageLayout.setVerticalGroup(
            profilePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 663, Short.MAX_VALUE)
        );

        mainTabbedPane.addTab("Profile Page", profilePage);

        javax.swing.GroupLayout editProjectsLayout = new javax.swing.GroupLayout(editProjects);
        editProjects.setLayout(editProjectsLayout);
        editProjectsLayout.setHorizontalGroup(
            editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 1367, Short.MAX_VALUE)
        );
        editProjectsLayout.setVerticalGroup(
            editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 663, Short.MAX_VALUE)
        );

        mainTabbedPane.addTab("Edit Projects", editProjects);

        javax.swing.GroupLayout mainPnlLayout = new javax.swing.GroupLayout(mainPnl);
        mainPnl.setLayout(mainPnlLayout);
        mainPnlLayout.setHorizontalGroup(
            mainPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(mainTabbedPane, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
        );
        mainPnlLayout.setVerticalGroup(
            mainPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPnlLayout.createSequentialGroup()
                .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(mainTabbedPane))
        );

        forgetPassPnl.setPreferredSize(new java.awt.Dimension(1366, 768));

        forgetPassLbl.setFont(new java.awt.Font("Segoe UI", 1, 48)); // NOI18N
        forgetPassLbl.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        forgetPassLbl.setText("Forget Password?");

        forgetInfoPnl.setFont(new java.awt.Font("Segoe UI", 2, 14)); // NOI18N
        forgetInfoPnl.setText("*Please provide your valid credentials to reset your password ");

        userForgetPnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "User Name", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        userForgetTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                userForgetTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout userForgetPnlLayout = new javax.swing.GroupLayout(userForgetPnl);
        userForgetPnl.setLayout(userForgetPnlLayout);
        userForgetPnlLayout.setHorizontalGroup(
            userForgetPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, userForgetPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(userForgetTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 299, Short.MAX_VALUE)
                .addContainerGap())
        );
        userForgetPnlLayout.setVerticalGroup(
            userForgetPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(userForgetPnlLayout.createSequentialGroup()
                .addComponent(userForgetTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 47, Short.MAX_VALUE)
                .addContainerGap())
        );

        emailForgetPnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Email Address", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        emailForgetTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                emailForgetTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout emailForgetPnlLayout = new javax.swing.GroupLayout(emailForgetPnl);
        emailForgetPnl.setLayout(emailForgetPnlLayout);
        emailForgetPnlLayout.setHorizontalGroup(
            emailForgetPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(emailForgetPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(emailForgetTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 299, Short.MAX_VALUE)
                .addContainerGap())
        );
        emailForgetPnlLayout.setVerticalGroup(
            emailForgetPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(emailForgetPnlLayout.createSequentialGroup()
                .addComponent(emailForgetTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 56, Short.MAX_VALUE)
                .addContainerGap())
        );

        passRForgetPnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Re-enter Password", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        passRForgetTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                passRForgetTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout passRForgetPnlLayout = new javax.swing.GroupLayout(passRForgetPnl);
        passRForgetPnl.setLayout(passRForgetPnlLayout);
        passRForgetPnlLayout.setHorizontalGroup(
            passRForgetPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, passRForgetPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(passRForgetTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 279, Short.MAX_VALUE)
                .addContainerGap())
        );
        passRForgetPnlLayout.setVerticalGroup(
            passRForgetPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passRForgetPnlLayout.createSequentialGroup()
                .addComponent(passRForgetTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 47, Short.MAX_VALUE)
                .addContainerGap())
        );

        passForgetPnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "New Password", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        passForgetTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                passForgetTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout passForgetPnlLayout = new javax.swing.GroupLayout(passForgetPnl);
        passForgetPnl.setLayout(passForgetPnlLayout);
        passForgetPnlLayout.setHorizontalGroup(
            passForgetPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, passForgetPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(passForgetTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 279, Short.MAX_VALUE)
                .addContainerGap())
        );
        passForgetPnlLayout.setVerticalGroup(
            passForgetPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passForgetPnlLayout.createSequentialGroup()
                .addComponent(passForgetTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 47, Short.MAX_VALUE)
                .addContainerGap())
        );

        submitBtn.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        submitBtn.setText("Submit");
        submitBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                submitBtnActionPerformed(evt);
            }
        });

        backForgetBtn.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        backForgetBtn.setText("Back");
        backForgetBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                backForgetBtnActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout forgetPassPnlLayout = new javax.swing.GroupLayout(forgetPassPnl);
        forgetPassPnl.setLayout(forgetPassPnlLayout);
        forgetPassPnlLayout.setHorizontalGroup(
            forgetPassPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, forgetPassPnlLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(passRForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(515, 515, 515))
            .addGroup(forgetPassPnlLayout.createSequentialGroup()
                .addGroup(forgetPassPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(forgetPassPnlLayout.createSequentialGroup()
                        .addGap(413, 413, 413)
                        .addComponent(forgetInfoPnl))
                    .addGroup(forgetPassPnlLayout.createSequentialGroup()
                        .addGap(291, 291, 291)
                        .addComponent(userForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(119, 119, 119)
                        .addComponent(emailForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(forgetPassPnlLayout.createSequentialGroup()
                        .addGap(624, 624, 624)
                        .addComponent(submitBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 118, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(135, 135, 135)
                        .addComponent(backForgetBtn))
                    .addGroup(forgetPassPnlLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(forgetPassLbl, javax.swing.GroupLayout.PREFERRED_SIZE, 1372, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(forgetPassPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, forgetPassPnlLayout.createSequentialGroup()
                    .addContainerGap(567, Short.MAX_VALUE)
                    .addComponent(passForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(516, 516, 516)))
        );
        forgetPassPnlLayout.setVerticalGroup(
            forgetPassPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(forgetPassPnlLayout.createSequentialGroup()
                .addGap(16, 16, 16)
                .addComponent(forgetPassLbl)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(forgetInfoPnl)
                .addGap(73, 73, 73)
                .addGroup(forgetPassPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(userForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(emailForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(128, 128, 128)
                .addComponent(passRForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(31, 31, 31)
                .addGroup(forgetPassPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(submitBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(backForgetBtn))
                .addContainerGap(221, Short.MAX_VALUE))
            .addGroup(forgetPassPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(forgetPassPnlLayout.createSequentialGroup()
                    .addGap(296, 296, 296)
                    .addComponent(passForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(392, Short.MAX_VALUE)))
        );

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        logoP.setIcon(new javax.swing.ImageIcon(getClass().getResource("/ProjectManagement/assests/projectM.jpg"))); // NOI18N

        logoLbl.setFont(new java.awt.Font("Segoe UI", 1, 36)); // NOI18N
        logoLbl.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        logoLbl.setText("Project Management System");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(34, 34, 34)
                        .addComponent(logoLbl, javax.swing.GroupLayout.PREFERRED_SIZE, 782, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(74, 74, 74)
                        .addComponent(logoP)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(57, 57, 57)
                .addComponent(logoLbl)
                .addGap(18, 18, 18)
                .addComponent(logoP)
                .addContainerGap(79, Short.MAX_VALUE))
        );

        logInLbl.setFont(new java.awt.Font("Segoe UI", 1, 24)); // NOI18N
        logInLbl.setText("Login Credential");

        userNamePnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "User Name", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        userLogInTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                userLogInTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout userNamePnlLayout = new javax.swing.GroupLayout(userNamePnl);
        userNamePnl.setLayout(userNamePnlLayout);
        userNamePnlLayout.setHorizontalGroup(
            userNamePnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, userNamePnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(userLogInTxtFld)
                .addContainerGap())
        );
        userNamePnlLayout.setVerticalGroup(
            userNamePnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(userNamePnlLayout.createSequentialGroup()
                .addComponent(userLogInTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 41, Short.MAX_VALUE)
                .addContainerGap())
        );

        passPnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Password", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        passLogInTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                passLogInTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout passPnlLayout = new javax.swing.GroupLayout(passPnl);
        passPnl.setLayout(passPnlLayout);
        passPnlLayout.setHorizontalGroup(
            passPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, passPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(passLogInTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 177, Short.MAX_VALUE)
                .addContainerGap())
        );
        passPnlLayout.setVerticalGroup(
            passPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passPnlLayout.createSequentialGroup()
                .addComponent(passLogInTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 41, Short.MAX_VALUE)
                .addContainerGap())
        );

        logInBtn.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        logInBtn.setText("Log In");
        logInBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                logInBtnActionPerformed(evt);
            }
        });

        forgetPasswordRadio.setText("Forget Password?");

        registerBtn.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        registerBtn.setText("Register");
        registerBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                registerBtnActionPerformed(evt);
            }
        });

        logo.setIcon(new javax.swing.ImageIcon(getClass().getResource("/ProjectManagement/assests/complete.png"))); // NOI18N

        javax.swing.GroupLayout logInPnlLayout = new javax.swing.GroupLayout(logInPnl);
        logInPnl.setLayout(logInPnlLayout);
        logInPnlLayout.setHorizontalGroup(
            logInPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(logInPnlLayout.createSequentialGroup()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, 786, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(62, 62, 62)
                .addGroup(logInPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(logInPnlLayout.createSequentialGroup()
                        .addGap(21, 21, 21)
                        .addGroup(logInPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(registerBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 144, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(logInBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 144, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(logInPnlLayout.createSequentialGroup()
                        .addGroup(logInPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(logInPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                .addComponent(logInLbl, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(userNamePnl, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(passPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(forgetPasswordRadio))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 77, Short.MAX_VALUE)
                        .addComponent(logo)
                        .addGap(42, 42, 42))))
        );
        logInPnlLayout.setVerticalGroup(
            logInPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(logInPnlLayout.createSequentialGroup()
                .addGap(54, 54, 54)
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(logInPnlLayout.createSequentialGroup()
                .addGap(208, 208, 208)
                .addGroup(logInPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(logInPnlLayout.createSequentialGroup()
                        .addComponent(logInLbl)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(userNamePnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(passPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(forgetPasswordRadio))
                    .addComponent(logo))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(logInBtn)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(registerBtn)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(logInPnl, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(logInPnl, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void userLogInTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_userLogInTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_userLogInTxtFldActionPerformed

    private void passLogInTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_passLogInTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_passLogInTxtFldActionPerformed

    private void logInBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_logInBtnActionPerformed
        // TODO add your handling code here:
        
        
        if (forgetPasswordRadio.isSelected()){
            logInPnl.setVisible(false);
            forgetPassPnl.setVisible(true);
             javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
                    getContentPane().setLayout(layout);
                    layout.setHorizontalGroup(
                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGap(0, 559, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(0, 0, Short.MAX_VALUE)
                                .addComponent(forgetPassPnl,
                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE)))
                    );
                    layout.setVerticalGroup(
                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGap(0, 382, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(0, 0, Short.MAX_VALUE)
                                .addComponent(forgetPassPnl,
                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE)))
                    );
        }else{
        String userName = userLogInTxtFld.getText();
        String passwordLogIn = String.valueOf(passLogInTxtFld.getText());
        
        if(!userName.isEmpty() || passwordLogIn.isEmpty()){
            try{
                Connection conn = setConnection();
                //Statement stm = conn.createStatement();
                PreparedStatement st = conn.prepareStatement("SELECT team_lead, password FROM registered_users WHERE team_lead=?");
                st.setString(1, userName);
                ResultSet set = st.executeQuery();
                boolean exists = false;
                while(set.next()){
                    String teamLead = set.getString("team_lead");
                    String passwordFromDB = set.getString("password");
                    if(passwordLogIn.equals(decrypt(teamLead, passwordFromDB))){
                        exists = true;
                    }
                }
                if (exists){
                    logInPnl.setVisible(false);
                    mainPnl.setVisible(true);
                    javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
                    getContentPane().setLayout(layout);
                    layout.setHorizontalGroup(
                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGap(0, 559, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(0, 0, Short.MAX_VALUE)
                                .addComponent(mainPnl,
                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE)))
                    );
                    layout.setVerticalGroup(
                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGap(0, 382, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(0, 0, Short.MAX_VALUE)
                                .addComponent(mainPnl,
                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE)))
                    );
                }else{
                        JOptionPane.showMessageDialog(logInPnl, "Invalid UserName/Password", "Error", JOptionPane.ERROR_MESSAGE);
                    }
            }catch(SQLException e){
                System.out.println("Error: " + e.getMessage());
            }catch(Exception e){
                System.out.println("Error: " + e.getMessage());
            }
        } else {
            JOptionPane.showMessageDialog(logInPnl, "Please fill up the details.", "Error", JOptionPane.ERROR_MESSAGE);
        }
        }
        
        
        
//        String londonMetId = LondonIDTextField.getText();
//        if (!londonMetId.isEmpty()) {
//            try {
//                String selectquery = "SELECT id FROM student_info";
//                ResultSet set = getResultSet(selectquery);
//
//                boolean exists = false;
//
//                while (set.next()) {
//                    String dbid = set.getString("id");
//                    //System.out.println(id);
//                    if (dbid.equals(londonMetId) || londonMetId.equals("admin")) {
//                        exists = true;
//                        break;
//                    } else {
//                        exists = false;
//                    }
//                }
//                if (exists) {
//                    logInPnl.setVisible(false);
//                    mainPnl.setVisible(true);
//                    errorMessageLbl.setVisible(false);
//                    javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
//                    getContentPane().setLayout(layout);
//                    layout.setHorizontalGroup(
//                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
//                        .addGap(0, 559, Short.MAX_VALUE)
//                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
//                            .addGroup(layout.createSequentialGroup()
//                                .addGap(0, 0, Short.MAX_VALUE)
//                                .addComponent(mainPnl,
//                                    javax.swing.GroupLayout.PREFERRED_SIZE,
//                                    javax.swing.GroupLayout.DEFAULT_SIZE,
//                                    javax.swing.GroupLayout.PREFERRED_SIZE)
//                                .addGap(0, 0, Short.MAX_VALUE)))
//                    );
//                    layout.setVerticalGroup(
//                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
//                        .addGap(0, 382, Short.MAX_VALUE)
//                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
//                            .addGroup(layout.createSequentialGroup()
//                                .addGap(0, 0, Short.MAX_VALUE)
//                                .addComponent(mainPnl,
//                                    javax.swing.GroupLayout.PREFERRED_SIZE,
//                                    javax.swing.GroupLayout.DEFAULT_SIZE,
//                                    javax.swing.GroupLayout.PREFERRED_SIZE)
//                                .addGap(0, 0, Short.MAX_VALUE)))
//                    );
//                }else{
//                    errorMessageLbl.setVisible(true);
//                    errorMessageLbl.setText("The London Met ID is not registered.");
//                }
//
//            } catch (SQLException e) {
//                System.out.println("Error:" + e.getMessage());
//            }
//
//        }else{
//            errorMessageLbl.setVisible(true);
//            errorMessageLbl.setText("Please fill out a valid London Met ID in input field.");
//        }
    }//GEN-LAST:event_logInBtnActionPerformed

    private void registerBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_registerBtnActionPerformed
        // TODO add your handling code here:
        logInPnl.setVisible(false);
        registerPnl.setVisible(true);
        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
                    getContentPane().setLayout(layout);
                    layout.setHorizontalGroup(
                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGap(0, 559, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(0, 0, Short.MAX_VALUE)
                                .addComponent(registerPnl,
                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE)))
                    );
                    layout.setVerticalGroup(
                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGap(0, 382, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(0, 0, Short.MAX_VALUE)
                                .addComponent(registerPnl,
                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE)))
                    );
    }//GEN-LAST:event_registerBtnActionPerformed
    private void extractTablesUsers() {
        //throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
        try{
        Connection conn = setConnection();
        PreparedStatement stm = conn.prepareStatement("SELECT * from registered_users");
        ResultSet set = stm.executeQuery();
        DefaultTableModel table = (DefaultTableModel) usersInfoTbl.getModel();
        table.setRowCount(0);
        while(set.next()){
            String teamLead =  set.getString("team_lead");
            String email = set.getString("email");
            String department = set.getString("department");
            String phoneNumber = set.getString("mobile_number");
            String[] info = {teamLead, email, department, phoneNumber};
            table.addRow(info);
        }
        }catch(SQLException e){
            System.out.println("Error: " + e.getMessage());
        }
    }
    
    private void extractTables() {
        //throw new UnsupportedOperationException("Not supported yet.");// Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
        try{
            Connection conn = setConnection();
            PreparedStatement stm = conn.prepareStatement("SELECT team_lead, project_name, assigned_date, due_date, completion_status FROM registered_projects");
            ResultSet set = stm.executeQuery();
            DefaultTableModel toDo = (DefaultTableModel)toDoTbl.getModel();
            DefaultTableModel doing = (DefaultTableModel)doingTbl.getModel();
            DefaultTableModel done = (DefaultTableModel)doneTbl.getModel();
            toDo.setRowCount(0);
            done.setRowCount(0);
            doing.setRowCount(0);
            System.out.println("I am here.");
            while(set.next()){
                String teamLead = set.getString("team_lead");
                System.out.println("teamLead");
                String project = set.getString("project_name");
                String assignedDate = set.getString("assigned_date");
                String dueDate = set.getString("due_date");
                //String completedDate = set.getString("completed_Date")
                //String completedRow[] = {project, teamLead, completedDate};
                String row[] = {project, teamLead, assignedDate, dueDate};
                String status = set.getString("completion_status");
                switch (status) {
                    case "To Do":
                        {
                            
                            toDo.addRow(row);
                            break;
                        }
                    case "Doing":
                        {
                            
                            doing.addRow(row);
                            break;
                        }
                    case "Done":
                        {
                            
                            done.addRow(row);
                            break;
                        }
                    default:
                        break;
                }
            }
        }catch(SQLException e)
        {
            System.out.println("Error:" + e.getMessage());
        }
    }
    
    private void userRegisterTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_userRegisterTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_userRegisterTxtFldActionPerformed

    private void passRegisterTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_passRegisterTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_passRegisterTxtFldActionPerformed

    private void emailRegisterTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_emailRegisterTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_emailRegisterTxtFldActionPerformed

    private void departRegisterTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_departRegisterTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_departRegisterTxtFldActionPerformed

    private void projectRegisterTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_projectRegisterTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_projectRegisterTxtFldActionPerformed

    private void costRegisterTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_costRegisterTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_costRegisterTxtFldActionPerformed

    private void assignedYearRActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_assignedYearRActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_assignedYearRActionPerformed

    private void assignedMonthRActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_assignedMonthRActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_assignedMonthRActionPerformed

    private void assignedDayRActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_assignedDayRActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_assignedDayRActionPerformed

    private void dueYearRActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dueYearRActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dueYearRActionPerformed

    private void dueMonthRActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dueMonthRActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dueMonthRActionPerformed

    private void dueDayRActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dueDayRActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dueDayRActionPerformed

    private void registerBtnRActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_registerBtnRActionPerformed
        // TODO add your handling code here:
        
        //getting the text from from text fields
        String teamLead = userRegisterTxtFld.getText();
        String password = passRegisterTxtFld.getText();
        String email = emailRegisterTxtFld.getText();
        String department = departRegisterTxtFld.getText();
        String mobile = mobileRegisterTxtFld.getText();
        String project = projectRegisterTxtFld.getText();
        String cost = costRegisterTxtFld.getText();
        String assignedDate = assignedYearR.getSelectedItem().toString() + "/" + assignedMonthR.getSelectedItem().toString() + "/" + assignedDayR.getSelectedItem().toString();
        String dueDate = dueYearR.getSelectedItem().toString() + "/" + dueMonthR.getSelectedItem().toString() + "/" + dueDayR.getSelectedItem().toString();
        
        String encryptedPass = "";
        try{
            encryptedPass = encrypt(teamLead, password);
        }catch(Exception e){
            System.out.println("Error: " + e.getMessage());
        }
        System.out.println(assignedDate);
        
        //dialog box if any text field is empty
        if(teamLead.equals("") || password.equals("") || email.equals("") || department.equals("") || project.equals("") || cost.equals("") || assignedDate.equals("") || dueDate.equals("")){
            JOptionPane.showMessageDialog(registerPnl, "Please provide the valid information.", "Error", JOptionPane.ERROR_MESSAGE);
        }
        
        //connection with database
        try{
            Connection conn = setConnection();
            PreparedStatement stmP = conn.prepareStatement("INSERT into registered_projects(project_name, assigned_date, due_date, completion_status,cost,team_lead, department)"
                    + "VALUES(?,?,?,?,?,?,?)");
            stmP.setString(1, project);
            stmP.setString(2, assignedDate);
            stmP.setString(3, dueDate);
            stmP.setString(4, "To Do");
            stmP.setString(5, cost);
            stmP.setString(6, teamLead);
            stmP.setString(7, department);
            int registerP = stmP.executeUpdate();
            
            PreparedStatement stmU = conn.prepareStatement("INSERT into registered_users(team_lead,email, password, department,mobile_number)"
                    + "VALUES(?,?,?,?,?)");
            stmU.setString(1, teamLead);
            stmU.setString(2, email);
            stmU.setString(3, encryptedPass);
            stmU.setString(4, department);
            stmU.setString(5, mobile);
            int registerU = stmU.executeUpdate();
            
            if(registerP == 1 && registerU == 1 ){
                JOptionPane.showMessageDialog(registerPnl, "Project has successfully been registered.", "Registered", JOptionPane.INFORMATION_MESSAGE);
            }else {
                JOptionPane.showMessageDialog(registerPnl, "Project cannot be registered at the moment.", "Error", JOptionPane.ERROR_MESSAGE);

            }
            
        }catch(SQLException e){
            System.out.println("Error: " + e.getMessage());
        }
//        String londonMetId = LondonIDTextField.getText();
//        if (!londonMetId.isEmpty()) {
//            try {
//                String selectquery = "SELECT id FROM student_info";
//                ResultSet set = getResultSet(selectquery);
//
//                boolean exists = false;
//
//                while (set.next()) {
//                    String dbid = set.getString("id");
//                    //System.out.println(id);
//                    if (dbid.equals(londonMetId) || londonMetId.equals("admin")) {
//                        exists = true;
//                        break;
//                    } else {
//                        exists = false;
//                    }
//                }
//                if (exists) {
//                    logInPnl.setVisible(false);
//                    mainPnl.setVisible(true);
//                    errorMessageLbl.setVisible(false);
//                    javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
//                    getContentPane().setLayout(layout);
//                    layout.setHorizontalGroup(
//                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
//                        .addGap(0, 559, Short.MAX_VALUE)
//                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
//                            .addGroup(layout.createSequentialGroup()
//                                .addGap(0, 0, Short.MAX_VALUE)
//                                .addComponent(mainPnl,
//                                    javax.swing.GroupLayout.PREFERRED_SIZE,
//                                    javax.swing.GroupLayout.DEFAULT_SIZE,
//                                    javax.swing.GroupLayout.PREFERRED_SIZE)
//                                .addGap(0, 0, Short.MAX_VALUE)))
//                    );
//                    layout.setVerticalGroup(
//                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
//                        .addGap(0, 382, Short.MAX_VALUE)
//                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
//                            .addGroup(layout.createSequentialGroup()
//                                .addGap(0, 0, Short.MAX_VALUE)
//                                .addComponent(mainPnl,
//                                    javax.swing.GroupLayout.PREFERRED_SIZE,
//                                    javax.swing.GroupLayout.DEFAULT_SIZE,
//                                    javax.swing.GroupLayout.PREFERRED_SIZE)
//                                .addGap(0, 0, Short.MAX_VALUE)))
//                    );
//                }else{
//                    errorMessageLbl.setVisible(true);
//                    errorMessageLbl.setText("The London Met ID is not registered.");
//                }
//
//            } catch (SQLException e) {
//                System.out.println("Error:" + e.getMessage());
//            }
//
//        }else{
//            errorMessageLbl.setVisible(true);
//            errorMessageLbl.setText("Please fill out a valid London Met ID in input field.");
//        }
    }//GEN-LAST:event_registerBtnRActionPerformed

    private void backBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_backBtnActionPerformed
        // TODO add your handling code here:
        registerPnl.setVisible(false);
        logInPnl.setVisible(true);
        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
                    getContentPane().setLayout(layout);
                    layout.setHorizontalGroup(
                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGap(0, 559, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(0, 0, Short.MAX_VALUE)
                                .addComponent(logInPnl,
                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE)))
                    );
                    layout.setVerticalGroup(
                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGap(0, 382, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(0, 0, Short.MAX_VALUE)
                                .addComponent(logInPnl,
                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE)))
                    );
    }//GEN-LAST:event_backBtnActionPerformed

    private void logOutBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_logOutBtnActionPerformed
        // TODO add your handling code here:
        mainPnl.setVisible(false);
        logInPnl.setVisible(true);
        //errorMessageLbl.setVisible(false);
        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 559, Short.MAX_VALUE)
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, Short.MAX_VALUE)
                    .addComponent(logInPnl,
                        javax.swing.GroupLayout.PREFERRED_SIZE,
                        javax.swing.GroupLayout.DEFAULT_SIZE,
                        javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 0, Short.MAX_VALUE)))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 382, Short.MAX_VALUE)
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, Short.MAX_VALUE)
                    .addComponent(logInPnl,
                        javax.swing.GroupLayout.PREFERRED_SIZE,
                        javax.swing.GroupLayout.DEFAULT_SIZE,
                        javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 0, Short.MAX_VALUE)))
        );
    }//GEN-LAST:event_logOutBtnActionPerformed

    private void jScrollBar1MouseWheelMoved(java.awt.event.MouseWheelEvent evt) {//GEN-FIRST:event_jScrollBar1MouseWheelMoved
        // TODO add your handling code here:
        
    }//GEN-LAST:event_jScrollBar1MouseWheelMoved

    private void mainTabbedPaneStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_mainTabbedPaneStateChanged
        // TODO add your handling code here:
        int value = mainTabbedPane.getSelectedIndex();
        switch (value){
            case 0:
                System.out.println("Home");
                break;
            case 1:
                System.out.println("View Projects");
                extractTables();
                break;
            case 2:
                System.out.println("View Users");
                extractTablesUsers();
                break;
            case 3:
                System.out.println("View Projects");
                break;
            case 4:
                System.out.println("Home");
                break;
        }
    }//GEN-LAST:event_mainTabbedPaneStateChanged

    private void mobileRegisterTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mobileRegisterTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_mobileRegisterTxtFldActionPerformed

    private void userForgetTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_userForgetTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_userForgetTxtFldActionPerformed

    private void emailForgetTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_emailForgetTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_emailForgetTxtFldActionPerformed

    private void passRForgetTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_passRForgetTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_passRForgetTxtFldActionPerformed

    private void passForgetTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_passForgetTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_passForgetTxtFldActionPerformed

    private void submitBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_submitBtnActionPerformed
        // TODO add your handling code here:
        //String userName = userForgetTxtFld.
    }//GEN-LAST:event_submitBtnActionPerformed

    private void backForgetBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_backForgetBtnActionPerformed
        // TODO add your handling code here:
        forgetPassPnl.setVisible(false);
        logInPnl.setVisible(true);
        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 559, Short.MAX_VALUE)
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, Short.MAX_VALUE)
                    .addComponent(logInPnl,
                        javax.swing.GroupLayout.PREFERRED_SIZE,
                        javax.swing.GroupLayout.DEFAULT_SIZE,
                        javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 0, Short.MAX_VALUE)))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 382, Short.MAX_VALUE)
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, Short.MAX_VALUE)
                    .addComponent(logInPnl,
                        javax.swing.GroupLayout.PREFERRED_SIZE,
                        javax.swing.GroupLayout.DEFAULT_SIZE,
                        javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 0, Short.MAX_VALUE)))
        );
    }//GEN-LAST:event_backForgetBtnActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(ProjectManagement.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(ProjectManagement.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(ProjectManagement.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(ProjectManagement.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new ProjectManagement().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel assignedDateLbl;
    private javax.swing.JComboBox<String> assignedDayR;
    private javax.swing.JComboBox<String> assignedMonthR;
    private javax.swing.JComboBox<String> assignedYearR;
    private javax.swing.JButton backBtn;
    private javax.swing.JButton backForgetBtn;
    private javax.swing.JPanel costRegisterPnl;
    private javax.swing.JTextField costRegisterTxtFld;
    private javax.swing.JPanel departRegisterPnl;
    private javax.swing.JTextField departRegisterTxtFld;
    private javax.swing.JLabel doingLbl;
    private javax.swing.JScrollPane doingPane;
    private javax.swing.JPanel doingPnl;
    private javax.swing.JTable doingTbl;
    private javax.swing.JLabel doneLbl;
    private javax.swing.JScrollPane donePane;
    private javax.swing.JPanel donePnl;
    private javax.swing.JTable doneTbl;
    private javax.swing.JLabel dueDateLbl;
    private javax.swing.JComboBox<String> dueDayR;
    private javax.swing.JComboBox<String> dueMonthR;
    private javax.swing.JComboBox<String> dueYearR;
    private javax.swing.JPanel editProjects;
    private javax.swing.JPanel emailForgetPnl;
    private javax.swing.JTextField emailForgetTxtFld;
    private javax.swing.JPanel emailRegisterPnl;
    private javax.swing.JTextField emailRegisterTxtFld;
    private javax.swing.JLabel forgetInfoPnl;
    private javax.swing.JLabel forgetPassLbl;
    private javax.swing.JPanel forgetPassPnl;
    private javax.swing.JRadioButton forgetPasswordRadio;
    private javax.swing.JPanel homePage;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JScrollBar jScrollBar1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JButton logInBtn;
    private javax.swing.JLabel logInLbl;
    private javax.swing.JPanel logInPnl;
    private javax.swing.JButton logOutBtn;
    private javax.swing.JLabel logo;
    private javax.swing.JLabel logoLbl;
    private javax.swing.JLabel logoP;
    private javax.swing.JPanel mainPnl;
    private java.awt.Label mainScreenLbl;
    private javax.swing.JTabbedPane mainTabbedPane;
    private javax.swing.JPanel mobileRegisterPnl;
    private javax.swing.JTextField mobileRegisterTxtFld;
    private javax.swing.JPanel passForgetPnl;
    private javax.swing.JTextField passForgetTxtFld;
    private javax.swing.JTextField passLogInTxtFld;
    private javax.swing.JPanel passPnl;
    private javax.swing.JPanel passRForgetPnl;
    private javax.swing.JTextField passRForgetTxtFld;
    private javax.swing.JPanel passRegisterPnl;
    private javax.swing.JTextField passRegisterTxtFld;
    private javax.swing.JPanel profilePage;
    private javax.swing.JPanel projectRegisterPnl;
    private javax.swing.JTextField projectRegisterTxtFld;
    private javax.swing.JPanel projectsPage;
    private javax.swing.JButton registerBtn;
    private javax.swing.JButton registerBtnR;
    private javax.swing.JLabel registerLbl;
    private javax.swing.JPanel registerPnl;
    private javax.swing.JLabel registerProjectLbl;
    private javax.swing.JButton submitBtn;
    private javax.swing.JLabel toDoLbl;
    private javax.swing.JScrollPane toDoPane;
    private javax.swing.JPanel toDoPnl;
    private javax.swing.JTable toDoTbl;
    private javax.swing.JPanel userForgetPnl;
    private javax.swing.JTextField userForgetTxtFld;
    private javax.swing.JTextField userLogInTxtFld;
    private javax.swing.JPanel userNamePnl;
    private javax.swing.JPanel userRegisterPnl;
    private javax.swing.JTextField userRegisterTxtFld;
    private javax.swing.JTable usersInfoTbl;
    private javax.swing.JPanel usersPage;
    // End of variables declaration//GEN-END:variables

    

    
}
