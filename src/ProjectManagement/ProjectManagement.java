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
import javax.swing.ImageIcon;
import javax.swing.JPanel;
import javax.swing.table.DefaultTableModel;
/**
 *
 * @author KAMAN
 */
public class ProjectManagement extends javax.swing.JFrame {
    int selectedRow;
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
        jLabel4 = new javax.swing.JLabel();
        nameLbl = new javax.swing.JLabel();
        userNameDisplay = new javax.swing.JLabel();
        emailLbl = new javax.swing.JLabel();
        emailDisplay = new javax.swing.JLabel();
        emailLbl1 = new javax.swing.JLabel();
        numberDisplay = new javax.swing.JLabel();
        departmentDisplay = new javax.swing.JLabel();
        emailLbl2 = new javax.swing.JLabel();
        jLabel9 = new javax.swing.JLabel();
        nameLbl1 = new javax.swing.JLabel();
        yourNameUpdate = new javax.swing.JLabel();
        departmentUpdatePnl = new javax.swing.JPanel();
        departmentUpdateTxtFld = new javax.swing.JTextField();
        emailUpdatePnl = new javax.swing.JPanel();
        emailUpdateTxtFld = new javax.swing.JTextField();
        numberUpdatePnl = new javax.swing.JPanel();
        numberUpdateTxtFld = new javax.swing.JTextField();
        updateInfoBtn = new javax.swing.JButton();
        jPanel4 = new javax.swing.JPanel();
        profilePhoto = new javax.swing.JLabel();
        editProjects = new javax.swing.JPanel();
        jScrollPane2 = new javax.swing.JScrollPane();
        editProjectsTbl = new javax.swing.JTable();
        updateProjectLbl = new javax.swing.JLabel();
        projectLbl = new javax.swing.JLabel();
        projectDisplayLbl = new javax.swing.JLabel();
        teamLeadLbl = new javax.swing.JLabel();
        teamLeadDisplayLbl = new javax.swing.JLabel();
        departmentLbl = new javax.swing.JLabel();
        departmentDisplayLbl = new javax.swing.JLabel();
        completionComboBox = new javax.swing.JComboBox<>();
        completionStatusLbl = new javax.swing.JLabel();
        assignedDatePLbl = new javax.swing.JLabel();
        assignedYearP = new javax.swing.JComboBox<>();
        assignedMonthP = new javax.swing.JComboBox<>();
        assignedDayP = new javax.swing.JComboBox<>();
        dueDateP = new javax.swing.JLabel();
        dueYearP = new javax.swing.JComboBox<>();
        dueMonthP = new javax.swing.JComboBox<>();
        dueDayP = new javax.swing.JComboBox<>();
        costUpdatePnl = new javax.swing.JPanel();
        costUpdateTxtFld = new javax.swing.JTextField();
        updateDateBtn = new javax.swing.JButton();
        completionDateP = new javax.swing.JLabel();
        completionYearP = new javax.swing.JComboBox<>();
        completionMonthP = new javax.swing.JComboBox<>();
        completionDayP = new javax.swing.JComboBox<>();
        changeStatusBtn = new javax.swing.JButton();
        deleteProjectBtn = new javax.swing.JButton();
        forgetPassPnl = new javax.swing.JPanel();
        forgetPassLbl = new javax.swing.JLabel();
        forgetInfoPnl = new javax.swing.JLabel();
        userForgetPnl = new javax.swing.JPanel();
        userForgetTxtFld = new javax.swing.JTextField();
        emailForgetPnl = new javax.swing.JPanel();
        emailForgetTxtFld = new javax.swing.JTextField();
        submitBtn = new javax.swing.JButton();
        passEnterPnl = new javax.swing.JPanel();
        passRForgetPnl = new javax.swing.JPanel();
        passRForgetTxtFld = new javax.swing.JPasswordField();
        passForgetPnl = new javax.swing.JPanel();
        passForgetTxtFld = new javax.swing.JPasswordField();
        backForgetBtn = new javax.swing.JButton();
        jPanel3 = new javax.swing.JPanel();
        validateBtn = new javax.swing.JButton();
        logInPnl = new javax.swing.JPanel();
        jPanel1 = new javax.swing.JPanel();
        logoP = new javax.swing.JLabel();
        logoLbl = new javax.swing.JLabel();
        logInLbl = new javax.swing.JLabel();
        userNamePnl = new javax.swing.JPanel();
        userLogInTxtFld = new javax.swing.JTextField();
        passPnl = new javax.swing.JPanel();
        passLogInTxtFld = new javax.swing.JPasswordField();
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

        jLabel4.setFont(new java.awt.Font("Segoe UI", 1, 36)); // NOI18N
        jLabel4.setText("Update your profile");

        nameLbl.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        nameLbl.setText("Your Name:");

        userNameDisplay.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        userNameDisplay.setText("your name");

        emailLbl.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        emailLbl.setText("Mobile Number:");

        emailDisplay.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        emailDisplay.setText("your email");

        emailLbl1.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        emailLbl1.setText("Email:");

        numberDisplay.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        numberDisplay.setText("your mobile number");

        departmentDisplay.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        departmentDisplay.setText("your department");

        emailLbl2.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        emailLbl2.setText("Department:");

        jLabel9.setFont(new java.awt.Font("Segoe UI", 1, 36)); // NOI18N
        jLabel9.setText("Profile");

        nameLbl1.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        nameLbl1.setText("Name:");

        yourNameUpdate.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        yourNameUpdate.setText("your name");

        departmentUpdatePnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Department", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        departmentUpdateTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                departmentUpdateTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout departmentUpdatePnlLayout = new javax.swing.GroupLayout(departmentUpdatePnl);
        departmentUpdatePnl.setLayout(departmentUpdatePnlLayout);
        departmentUpdatePnlLayout.setHorizontalGroup(
            departmentUpdatePnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(departmentUpdatePnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(departmentUpdateTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 299, Short.MAX_VALUE)
                .addContainerGap())
        );
        departmentUpdatePnlLayout.setVerticalGroup(
            departmentUpdatePnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(departmentUpdatePnlLayout.createSequentialGroup()
                .addComponent(departmentUpdateTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 58, Short.MAX_VALUE)
                .addContainerGap())
        );

        emailUpdatePnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Email Address", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        emailUpdateTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                emailUpdateTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout emailUpdatePnlLayout = new javax.swing.GroupLayout(emailUpdatePnl);
        emailUpdatePnl.setLayout(emailUpdatePnlLayout);
        emailUpdatePnlLayout.setHorizontalGroup(
            emailUpdatePnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(emailUpdatePnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(emailUpdateTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 299, Short.MAX_VALUE)
                .addContainerGap())
        );
        emailUpdatePnlLayout.setVerticalGroup(
            emailUpdatePnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(emailUpdatePnlLayout.createSequentialGroup()
                .addComponent(emailUpdateTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 56, Short.MAX_VALUE)
                .addContainerGap())
        );

        numberUpdatePnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Mobile Number", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        numberUpdateTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                numberUpdateTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout numberUpdatePnlLayout = new javax.swing.GroupLayout(numberUpdatePnl);
        numberUpdatePnl.setLayout(numberUpdatePnlLayout);
        numberUpdatePnlLayout.setHorizontalGroup(
            numberUpdatePnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(numberUpdatePnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(numberUpdateTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 321, Short.MAX_VALUE)
                .addContainerGap())
        );
        numberUpdatePnlLayout.setVerticalGroup(
            numberUpdatePnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(numberUpdatePnlLayout.createSequentialGroup()
                .addComponent(numberUpdateTxtFld)
                .addContainerGap())
        );

        updateInfoBtn.setBackground(new java.awt.Color(51, 51, 51));
        updateInfoBtn.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        updateInfoBtn.setForeground(new java.awt.Color(204, 204, 204));
        updateInfoBtn.setText("Update");
        updateInfoBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                updateInfoBtnActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 149, Short.MAX_VALUE)
            .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel4Layout.createSequentialGroup()
                    .addGap(50, 50, 50)
                    .addComponent(profilePhoto)
                    .addContainerGap(99, Short.MAX_VALUE)))
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 143, Short.MAX_VALUE)
            .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel4Layout.createSequentialGroup()
                    .addGap(50, 50, 50)
                    .addComponent(profilePhoto)
                    .addContainerGap(93, Short.MAX_VALUE)))
        );

        javax.swing.GroupLayout profilePageLayout = new javax.swing.GroupLayout(profilePage);
        profilePage.setLayout(profilePageLayout);
        profilePageLayout.setHorizontalGroup(
            profilePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(profilePageLayout.createSequentialGroup()
                .addGap(128, 128, 128)
                .addGroup(profilePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(profilePageLayout.createSequentialGroup()
                        .addComponent(emailUpdatePnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(65, 65, 65)
                        .addComponent(numberUpdatePnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(30, 30, 30)
                        .addComponent(departmentUpdatePnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(profilePageLayout.createSequentialGroup()
                        .addGap(51, 51, 51)
                        .addComponent(jPanel4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(200, 200, 200)
                        .addGroup(profilePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel9)
                            .addGroup(profilePageLayout.createSequentialGroup()
                                .addGroup(profilePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(emailLbl1)
                                    .addComponent(nameLbl1)
                                    .addComponent(emailLbl2)
                                    .addComponent(emailLbl))
                                .addGap(53, 53, 53)
                                .addGroup(profilePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(numberDisplay)
                                    .addComponent(emailDisplay)
                                    .addComponent(userNameDisplay)
                                    .addComponent(departmentDisplay)))))
                    .addComponent(jLabel4)
                    .addGroup(profilePageLayout.createSequentialGroup()
                        .addComponent(nameLbl)
                        .addGap(83, 83, 83)
                        .addComponent(yourNameUpdate)))
                .addContainerGap(159, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, profilePageLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(updateInfoBtn)
                .addGap(601, 601, 601))
        );
        profilePageLayout.setVerticalGroup(
            profilePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(profilePageLayout.createSequentialGroup()
                .addGap(45, 45, 45)
                .addGroup(profilePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(profilePageLayout.createSequentialGroup()
                        .addComponent(jLabel9)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(profilePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(nameLbl1)
                            .addComponent(userNameDisplay))
                        .addGap(7, 7, 7)
                        .addGroup(profilePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(emailLbl1)
                            .addComponent(emailDisplay))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(profilePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(emailLbl)
                            .addComponent(numberDisplay)))
                    .addComponent(jPanel4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(profilePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(emailLbl2)
                    .addComponent(departmentDisplay))
                .addGap(82, 82, 82)
                .addComponent(jLabel4)
                .addGap(18, 18, 18)
                .addGroup(profilePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(nameLbl)
                    .addComponent(yourNameUpdate))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(profilePageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(emailUpdatePnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(departmentUpdatePnl, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(numberUpdatePnl, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(updateInfoBtn)
                .addContainerGap(120, Short.MAX_VALUE))
        );

        mainTabbedPane.addTab("Profile Page", profilePage);

        editProjectsTbl.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null, null, null, null, null},
                {null, null, null, null, null, null, null, null},
                {null, null, null, null, null, null, null, null},
                {null, null, null, null, null, null, null, null}
            },
            new String [] {
                "Project Name", "Team Lead", "Department Name", "Assigned Date", "Due Date", "Completion Status", "Completion Date", "Cost"
            }
        ) {
            boolean[] canEdit = new boolean [] {
                false, false, false, false, false, false, false, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        editProjectsTbl.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                editProjectsTblMouseClicked(evt);
            }
        });
        jScrollPane2.setViewportView(editProjectsTbl);

        updateProjectLbl.setFont(new java.awt.Font("Segoe UI", 1, 24)); // NOI18N
        updateProjectLbl.setText("Update your projects");

        projectLbl.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        projectLbl.setText("Project Name: ");

        projectDisplayLbl.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        projectDisplayLbl.setText("Choose your project");

        teamLeadLbl.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        teamLeadLbl.setText("Team Lead:");

        teamLeadDisplayLbl.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        teamLeadDisplayLbl.setText("Team's lead name");

        departmentLbl.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        departmentLbl.setText("Department:");

        departmentDisplayLbl.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        departmentDisplayLbl.setText("Department's name");

        completionComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Doing", "Done" }));

        completionStatusLbl.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        completionStatusLbl.setText("Completion Status:");

        assignedDatePLbl.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        assignedDatePLbl.setText("Assigned Date");

        assignedYearP.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        assignedYearP.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026", " " }));
        assignedYearP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                assignedYearPActionPerformed(evt);
            }
        });

        assignedMonthP.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        assignedMonthP.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", " " }));
        assignedMonthP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                assignedMonthPActionPerformed(evt);
            }
        });

        assignedDayP.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        assignedDayP.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", " ", " " }));
        assignedDayP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                assignedDayPActionPerformed(evt);
            }
        });

        dueDateP.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        dueDateP.setText("Due Date");

        dueYearP.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        dueYearP.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026", " " }));
        dueYearP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dueYearPActionPerformed(evt);
            }
        });

        dueMonthP.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        dueMonthP.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", " " }));
        dueMonthP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dueMonthPActionPerformed(evt);
            }
        });

        dueDayP.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        dueDayP.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", " ", " " }));
        dueDayP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dueDayPActionPerformed(evt);
            }
        });

        costUpdatePnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Cost", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        costUpdateTxtFld.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                costUpdateTxtFldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout costUpdatePnlLayout = new javax.swing.GroupLayout(costUpdatePnl);
        costUpdatePnl.setLayout(costUpdatePnlLayout);
        costUpdatePnlLayout.setHorizontalGroup(
            costUpdatePnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(costUpdatePnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(costUpdateTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 248, Short.MAX_VALUE)
                .addContainerGap())
        );
        costUpdatePnlLayout.setVerticalGroup(
            costUpdatePnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(costUpdatePnlLayout.createSequentialGroup()
                .addComponent(costUpdateTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 36, Short.MAX_VALUE)
                .addContainerGap())
        );

        updateDateBtn.setBackground(new java.awt.Color(51, 51, 51));
        updateDateBtn.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        updateDateBtn.setForeground(new java.awt.Color(204, 204, 204));
        updateDateBtn.setText("Save Changes");
        updateDateBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                updateDateBtnActionPerformed(evt);
            }
        });

        completionDateP.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        completionDateP.setText("Completion Status");

        completionYearP.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        completionYearP.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026", " " }));
        completionYearP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                completionYearPActionPerformed(evt);
            }
        });

        completionMonthP.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        completionMonthP.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", " " }));
        completionMonthP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                completionMonthPActionPerformed(evt);
            }
        });

        completionDayP.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        completionDayP.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", " ", " " }));
        completionDayP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                completionDayPActionPerformed(evt);
            }
        });

        changeStatusBtn.setBackground(new java.awt.Color(51, 51, 51));
        changeStatusBtn.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        changeStatusBtn.setForeground(new java.awt.Color(204, 204, 204));
        changeStatusBtn.setText("Change status");
        changeStatusBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                changeStatusBtnActionPerformed(evt);
            }
        });

        deleteProjectBtn.setBackground(new java.awt.Color(51, 51, 51));
        deleteProjectBtn.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        deleteProjectBtn.setForeground(new java.awt.Color(204, 204, 204));
        deleteProjectBtn.setText("Delete Project");
        deleteProjectBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                deleteProjectBtnActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout editProjectsLayout = new javax.swing.GroupLayout(editProjects);
        editProjects.setLayout(editProjectsLayout);
        editProjectsLayout.setHorizontalGroup(
            editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(editProjectsLayout.createSequentialGroup()
                .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, editProjectsLayout.createSequentialGroup()
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 1345, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(editProjectsLayout.createSequentialGroup()
                        .addGap(40, 40, 40)
                        .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(updateProjectLbl)
                            .addGroup(editProjectsLayout.createSequentialGroup()
                                .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(projectLbl)
                                    .addComponent(teamLeadLbl)
                                    .addComponent(departmentLbl))
                                .addGap(18, 18, 18)
                                .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(teamLeadDisplayLbl)
                                    .addComponent(projectDisplayLbl)
                                    .addComponent(departmentDisplayLbl))
                                .addGap(118, 118, 118)
                                .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addGroup(editProjectsLayout.createSequentialGroup()
                                        .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, editProjectsLayout.createSequentialGroup()
                                                .addGap(86, 86, 86)
                                                .addComponent(assignedDatePLbl)
                                                .addGap(71, 71, 71))
                                            .addGroup(editProjectsLayout.createSequentialGroup()
                                                .addComponent(assignedYearP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addGap(18, 18, 18)
                                                .addComponent(assignedMonthP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addGap(18, 18, 18)
                                                .addComponent(assignedDayP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                                        .addGap(41, 41, 41)
                                        .addComponent(dueYearP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                    .addComponent(updateDateBtn))
                                .addGap(18, 18, 18)
                                .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(editProjectsLayout.createSequentialGroup()
                                        .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addGroup(editProjectsLayout.createSequentialGroup()
                                                .addComponent(dueMonthP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addGap(18, 18, 18)
                                                .addComponent(dueDayP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                            .addComponent(dueDateP))
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(costUpdatePnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(77, 77, 77))
                                    .addGroup(editProjectsLayout.createSequentialGroup()
                                        .addGap(171, 171, 171)
                                        .addComponent(deleteProjectBtn)
                                        .addGap(0, 0, Short.MAX_VALUE)))))))
                .addContainerGap())
            .addGroup(editProjectsLayout.createSequentialGroup()
                .addGap(292, 292, 292)
                .addComponent(completionYearP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(editProjectsLayout.createSequentialGroup()
                        .addComponent(completionMonthP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(completionDayP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(completionDateP))
                .addGap(66, 66, 66)
                .addComponent(completionStatusLbl)
                .addGap(18, 18, 18)
                .addComponent(completionComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(81, 81, 81)
                .addComponent(changeStatusBtn)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        editProjectsLayout.setVerticalGroup(
            editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(editProjectsLayout.createSequentialGroup()
                .addContainerGap(15, Short.MAX_VALUE)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 246, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(updateProjectLbl)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(editProjectsLayout.createSequentialGroup()
                        .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(projectLbl)
                            .addComponent(projectDisplayLbl))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(teamLeadLbl)
                            .addComponent(teamLeadDisplayLbl))
                        .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(departmentLbl)
                            .addComponent(departmentDisplayLbl)))
                    .addGroup(editProjectsLayout.createSequentialGroup()
                        .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addGroup(editProjectsLayout.createSequentialGroup()
                                .addComponent(dueDateP)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(dueYearP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(dueMonthP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(dueDayP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                            .addGroup(editProjectsLayout.createSequentialGroup()
                                .addComponent(assignedDatePLbl)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(assignedYearP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(assignedMonthP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(assignedDayP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                            .addComponent(costUpdatePnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(29, 29, 29)
                        .addComponent(updateDateBtn)))
                .addGap(15, 15, 15)
                .addComponent(deleteProjectBtn)
                .addGap(25, 25, 25)
                .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(editProjectsLayout.createSequentialGroup()
                        .addComponent(completionDateP)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(completionYearP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(completionMonthP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(completionDayP, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, editProjectsLayout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 11, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGroup(editProjectsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(completionStatusLbl)
                            .addComponent(completionComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(changeStatusBtn))
                        .addGap(6, 6, 6)))
                .addGap(98, 98, 98))
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
                .addComponent(userForgetTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 61, Short.MAX_VALUE)
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
                .addComponent(emailForgetTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 52, Short.MAX_VALUE)
                .addContainerGap())
        );

        submitBtn.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        submitBtn.setText("Submit");
        submitBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                submitBtnActionPerformed(evt);
            }
        });

        passRForgetPnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Re-enter Password", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        javax.swing.GroupLayout passRForgetPnlLayout = new javax.swing.GroupLayout(passRForgetPnl);
        passRForgetPnl.setLayout(passRForgetPnlLayout);
        passRForgetPnlLayout.setHorizontalGroup(
            passRForgetPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passRForgetPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(passRForgetTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 294, Short.MAX_VALUE)
                .addContainerGap())
        );
        passRForgetPnlLayout.setVerticalGroup(
            passRForgetPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passRForgetPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(passRForgetTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 51, Short.MAX_VALUE)
                .addContainerGap())
        );

        passForgetPnl.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "New Password", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Segoe UI", 1, 14))); // NOI18N

        javax.swing.GroupLayout passForgetPnlLayout = new javax.swing.GroupLayout(passForgetPnl);
        passForgetPnl.setLayout(passForgetPnlLayout);
        passForgetPnlLayout.setHorizontalGroup(
            passForgetPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passForgetPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(passForgetTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 294, Short.MAX_VALUE)
                .addContainerGap())
        );
        passForgetPnlLayout.setVerticalGroup(
            passForgetPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passForgetPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(passForgetTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 52, Short.MAX_VALUE)
                .addContainerGap())
        );

        javax.swing.GroupLayout passEnterPnlLayout = new javax.swing.GroupLayout(passEnterPnl);
        passEnterPnl.setLayout(passEnterPnlLayout);
        passEnterPnlLayout.setHorizontalGroup(
            passEnterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passEnterPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(passForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(20, Short.MAX_VALUE))
            .addGroup(passEnterPnlLayout.createSequentialGroup()
                .addComponent(passRForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );
        passEnterPnlLayout.setVerticalGroup(
            passEnterPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, passEnterPnlLayout.createSequentialGroup()
                .addGap(19, 19, 19)
                .addComponent(passForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 94, Short.MAX_VALUE)
                .addComponent(passRForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        backForgetBtn.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        backForgetBtn.setText("Back");
        backForgetBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                backForgetBtnActionPerformed(evt);
            }
        });

        validateBtn.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        validateBtn.setText("Validate");
        validateBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                validateBtnActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(validateBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 118, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel3Layout.createSequentialGroup()
                .addGap(0, 8, Short.MAX_VALUE)
                .addComponent(validateBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        javax.swing.GroupLayout forgetPassPnlLayout = new javax.swing.GroupLayout(forgetPassPnl);
        forgetPassPnl.setLayout(forgetPassPnlLayout);
        forgetPassPnlLayout.setHorizontalGroup(
            forgetPassPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(forgetPassPnlLayout.createSequentialGroup()
                .addGroup(forgetPassPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(forgetPassPnlLayout.createSequentialGroup()
                        .addGap(291, 291, 291)
                        .addGroup(forgetPassPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(forgetPassPnlLayout.createSequentialGroup()
                                .addComponent(userForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addGroup(forgetPassPnlLayout.createSequentialGroup()
                                .addComponent(emailForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, forgetPassPnlLayout.createSequentialGroup()
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGroup(forgetPassPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(submitBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 118, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(122, 122, 122)))
                .addComponent(passEnterPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(135, 135, 135))
            .addGroup(forgetPassPnlLayout.createSequentialGroup()
                .addGroup(forgetPassPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(forgetPassPnlLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(forgetPassLbl, javax.swing.GroupLayout.PREFERRED_SIZE, 1372, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(forgetPassPnlLayout.createSequentialGroup()
                        .addGap(503, 503, 503)
                        .addComponent(forgetInfoPnl)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, forgetPassPnlLayout.createSequentialGroup()
                .addGap(0, 0, Short.MAX_VALUE)
                .addComponent(backForgetBtn)
                .addGap(345, 345, 345))
        );
        forgetPassPnlLayout.setVerticalGroup(
            forgetPassPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(forgetPassPnlLayout.createSequentialGroup()
                .addGap(16, 16, 16)
                .addComponent(forgetPassLbl)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 58, Short.MAX_VALUE)
                .addComponent(forgetInfoPnl)
                .addGroup(forgetPassPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(forgetPassPnlLayout.createSequentialGroup()
                        .addGap(55, 55, 55)
                        .addComponent(passEnterPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(forgetPassPnlLayout.createSequentialGroup()
                        .addGap(87, 87, 87)
                        .addComponent(userForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(35, 35, 35)
                        .addComponent(emailForgetPnl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(39, 39, 39)
                .addComponent(submitBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(backForgetBtn)
                .addGap(144, 144, 144))
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

        javax.swing.GroupLayout passPnlLayout = new javax.swing.GroupLayout(passPnl);
        passPnl.setLayout(passPnlLayout);
        passPnlLayout.setHorizontalGroup(
            passPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(passLogInTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 177, Short.MAX_VALUE)
                .addContainerGap())
        );
        passPnlLayout.setVerticalGroup(
            passPnlLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passPnlLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(passLogInTxtFld, javax.swing.GroupLayout.DEFAULT_SIZE, 35, Short.MAX_VALUE)
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
                    passEnterPnl.setVisible(false);
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
            PreparedStatement stm = conn.prepareStatement("SELECT team_lead, project_name, assigned_date, due_date, completion_status, completion_date FROM registered_projects");
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
                String completedDate = set.getString("completion_date");
                String completedRow[] = {project, teamLead, completedDate};
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
                            
                            done.addRow(completedRow);
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
        try{
            Connection conn = setConnection();
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
        
        PreparedStatement stm = conn.prepareStatement("SELECT * FROM registered_users");
        ResultSet emailSet = stm.executeQuery();
        boolean exists = false;
        while(emailSet.next()){
            String emailDB = emailSet.getString("email");
            if(email.equals(emailDB)){
                exists = true;
                break;
            }
        }
        if(!exists){
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
            
             PreparedStatement stmU = conn.prepareStatement("INSERT into registered_users(team_lead,email, password, department,mobile_number)"
                    + "VALUES(?,?,?,?,?)");
            stmU.setString(1, teamLead);
            stmU.setString(2, email);
            stmU.setString(3, encryptedPass);
            stmU.setString(4, department);
            stmU.setString(5, mobile);
            int registerU = stmU.executeUpdate();
            
            PreparedStatement stmId = conn.prepareStatement("SELECT id FROM registered_users WHERE email = ?");
            stmId.setString(1, email);
            ResultSet set = stmId.executeQuery();
            String userId = null;
            while(set.next()){
                userId = set.getString("id");
            }
            PreparedStatement stmP = conn.prepareStatement("INSERT into registered_projects(project_name, assigned_date, due_date, completion_status,cost,team_lead, department, user_id)"
                    + "VALUES(?,?,?,?,?,?,?,?)");
            stmP.setString(1, project);
            stmP.setString(2, assignedDate);
            stmP.setString(3, dueDate);
            stmP.setString(4, "To Do");
            stmP.setString(5, cost);
            stmP.setString(6, teamLead);
            stmP.setString(7, department);
            stmP.setString(8, userId);
            int registerP = stmP.executeUpdate();
            
           
            
            if(registerP == 1 && registerU == 1 ){
                clearTextFields();
                JOptionPane.showMessageDialog(registerPnl, "Project has successfully been registered.", "Registered", JOptionPane.INFORMATION_MESSAGE);
            }else {
                JOptionPane.showMessageDialog(registerPnl, "Project cannot be registered at the moment.", "Error", JOptionPane.ERROR_MESSAGE);

            }
        
        }else{
            JOptionPane.showMessageDialog(registerPnl, "Please provide a valid email." ,"Error", JOptionPane.ERROR_MESSAGE);

                }
        } catch (SQLException ex) {
            JOptionPane.showMessageDialog(registerPnl, "Please provide valid credentials." ,"Error", JOptionPane.ERROR_MESSAGE);
            Logger.getLogger(ProjectManagement.class.getName()).log(Level.SEVERE, null, ex);
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
        backToLogIn(registerPnl);
        
    }//GEN-LAST:event_backBtnActionPerformed

    private void logOutBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_logOutBtnActionPerformed
        // TODO add your handling code here:
        backToLogIn(mainPnl);
        userLogInTxtFld.setText("");
        passLogInTxtFld.setText("");
        forgetPasswordRadio.setSelected(false);
        
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
                System.out.println("View Profile");
                generateProfile();
                break;
            case 4:
                System.out.println("Edit Projects");
                generateProjectTable();
                break;
        }
    }//GEN-LAST:event_mainTabbedPaneStateChanged
    
    private void generateProjectTable(){
        try {
            Connection conn = setConnection();
            PreparedStatement stm = conn.prepareStatement("SELECT * FROM registered_projects");
            ResultSet set = stm.executeQuery();
            DefaultTableModel table = (DefaultTableModel) editProjectsTbl.getModel();
            table.setRowCount(0);
            while(set.next()){
                String project = set.getString("project_name");
                String teamLead = set.getString("team_lead");
                String assignedDate = set.getString("assigned_date");
                String dueDate = set.getString("due_date");
                String status = set.getString("completion_status");
                String completionDate = set.getString("completion_date");
                String department = set.getString("department");
                String cost = set.getString("cost");
                String[] row = {project, teamLead, department, assignedDate, dueDate,status, completionDate,cost};
                table.addRow(row);
                        
            }
            
        } catch (SQLException ex) {
            Logger.getLogger(ProjectManagement.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private void generateProfile(){
        try{
        //getting the team_lead and password from the log in page
        String userName = userLogInTxtFld.getText();
        char[] passwordInArr = passLogInTxtFld.getPassword();
        String password = "";
        for(char each: passwordInArr){
            password += each;
        }
            System.out.println(password);
        
        Connection conn = setConnection();
        PreparedStatement stm = conn.prepareStatement("SELECT * FROM registered_users WHERE team_lead = ?");
        stm.setString(1, userName);
        ResultSet set = stm.executeQuery();
            System.out.println(set);
        String team_lead = null, email = null, department = null, number = null, imageResource = null;
        
        while(set.next()){
            String passwordDB = decrypt(set.getString("team_lead"),set.getString("password"));
            if(passwordDB.equals(password)){
                team_lead = set.getString("team_lead");
                System.out.println(team_lead);
                email = set.getString("email");
                department = set.getString("department");
                number = set.getString("mobile_number");
                imageResource = set.getString("user_image");
            }
        }
        userNameDisplay.setText(team_lead);
        emailDisplay.setText(email);
        departmentDisplay.setText(department);
        numberDisplay.setText(number);
        yourNameUpdate.setText(team_lead);
            System.out.println(imageResource);
//       profilePhoto.setIcon(profileImage);
//        profileImage.getClass().getResource(imageResource); //what does getClass do //why doesnot it work like below
//            System.out.println(profileImage);
//        profilePhoto.setIcon(profileImage);
        profilePhoto.setIcon(new javax.swing.ImageIcon(getClass().getResource(imageResource))); // NOI18N

        }catch(SQLException e){
            System.out.println("Error: " + e.getMessage());
        } catch (Exception ex) {
            Logger.getLogger(ProjectManagement.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    
    private void mobileRegisterTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mobileRegisterTxtFldActionPerformed
        // TODO add your handling code here:
        
    }//GEN-LAST:event_mobileRegisterTxtFldActionPerformed

    private void validateBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_validateBtnActionPerformed
        // TODO add your handling code here:
        try{
        String userName = userForgetTxtFld.getText();
        String email = emailForgetTxtFld.getText();
        Connection conn = setConnection();
        PreparedStatement stm = conn.prepareStatement("SELECT * FROM registered_users");
        ResultSet set = stm.executeQuery();
        boolean exists = false; 
        while(set.next()){
            String team_lead = set.getString("team_lead");
            String emailDB = set.getString("email");
            if(userName.equals(team_lead) && email.equals(emailDB)){
                validateBtn.setVisible(false);
                passEnterPnl.setVisible(true);
                exists = true;
            }
        }
        if(!exists){
            JOptionPane.showMessageDialog(forgetPassPnl, "Please enter valid credentials.", "Error", JOptionPane.ERROR_MESSAGE);
        }
        }catch(SQLException e){
            System.out.println("Error:" + e.getMessage());
        }
    }//GEN-LAST:event_validateBtnActionPerformed

    private void submitBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_submitBtnActionPerformed
        // TODO add your handling code here:
        try{
            String userName = userForgetTxtFld.getText();
            String email = emailForgetTxtFld.getText();
            String newPass = passForgetTxtFld.getText();
            String reEnterPass = passRForgetTxtFld.getText();
            boolean checkEqual = false;
            if(newPass.equals(reEnterPass)){
                checkEqual = true;
            }
            if(checkEqual){
            Connection conn = setConnection();
            PreparedStatement stm = conn.prepareStatement("UPDATE registered_users SET password = ? where email = ?");
                try {
                    stm.setString(1, encrypt(userName, newPass));
                } catch (Exception ex) {
                    Logger.getLogger(ProjectManagement.class.getName()).log(Level.SEVERE, null, ex);
                }
            stm.setString(2, email);
            int set = stm.executeUpdate();
            if(set == 1){
                JOptionPane.showMessageDialog(forgetPassPnl, "Your password has been updated.", "Info", JOptionPane.INFORMATION_MESSAGE);
                backToLogIn(forgetPassPnl);
            }
            } else {
                JOptionPane.showMessageDialog(forgetPassPnl, "The re-entered password doesnot match. Please enter valid password.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        }catch(SQLException e){
            System.out.println("Error: " + e.getMessage());
        }
    }//GEN-LAST:event_submitBtnActionPerformed

    private void backForgetBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_backForgetBtnActionPerformed
        // TODO add your handling code here:
        backToLogIn(forgetPassPnl);
        
    }//GEN-LAST:event_backForgetBtnActionPerformed

    private void emailForgetTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_emailForgetTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_emailForgetTxtFldActionPerformed

    private void userForgetTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_userForgetTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_userForgetTxtFldActionPerformed

    private void emailUpdateTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_emailUpdateTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_emailUpdateTxtFldActionPerformed

    private void numberUpdateTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_numberUpdateTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_numberUpdateTxtFldActionPerformed

    private void departmentUpdateTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_departmentUpdateTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_departmentUpdateTxtFldActionPerformed

    private void updateInfoBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_updateInfoBtnActionPerformed
        try {
            // TODO add your handling code here:
            String emailDB = emailDisplay.getText();
            String emailUpdate = emailUpdateTxtFld.getText();
            String phoneNumber = numberUpdateTxtFld.getText();
            String department = departmentUpdateTxtFld.getText();
            Connection conn = setConnection();
            PreparedStatement stmID = conn.prepareStatement("SELECT id FROM registered_users where email = ?");
            stmID.setString(1, emailDB);
            ResultSet setID = stmID.executeQuery();
            String userID = null;
            while(setID.next()){
                userID = setID.getString("id");
            }
            PreparedStatement stmDepart = conn.prepareStatement("UPDATE registered_projects SET department = ? WHERE user_id = ?");
            stmDepart.setString(1, department);
            stmDepart.setString(2, userID);
            int setDepart = stmDepart.executeUpdate();
            PreparedStatement stm = conn.prepareStatement("UPDATE registered_users SET email = ?, mobile_number = ?, department = ? WHERE email = ?");
            stm.setString(1, emailUpdate);
            stm.setString(2, phoneNumber);
            stm.setString(3, department);
            stm.setString(4, emailDB);
            int set = stm.executeUpdate();
            if(set == 1 && setDepart == 1){
                clearTextFields();
                JOptionPane.showMessageDialog(profilePage, "The info has been updated.", "Success", JOptionPane.INFORMATION_MESSAGE);
                generateProfile();
            }
        } catch (SQLException ex) {
            Logger.getLogger(ProjectManagement.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_updateInfoBtnActionPerformed

    private void assignedYearPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_assignedYearPActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_assignedYearPActionPerformed

    private void assignedMonthPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_assignedMonthPActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_assignedMonthPActionPerformed

    private void assignedDayPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_assignedDayPActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_assignedDayPActionPerformed

    private void dueYearPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dueYearPActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dueYearPActionPerformed

    private void dueMonthPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dueMonthPActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dueMonthPActionPerformed

    private void dueDayPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dueDayPActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dueDayPActionPerformed

    private void costUpdateTxtFldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_costUpdateTxtFldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_costUpdateTxtFldActionPerformed

    private void updateDateBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_updateDateBtnActionPerformed
        try {
            // TODO add your handling code here:
            String projectName = projectDisplayLbl.getText();
            String newAssignedDate = assignedYearP.getSelectedItem().toString() + "/" + assignedMonthP.getSelectedItem().toString() + "/" + assignedDayP.getSelectedItem().toString();
            String newDueDate = dueYearP.getSelectedItem().toString() + "/" + dueMonthP.getSelectedItem().toString() + "/" + dueDayP.getSelectedItem().toString();
            String newCost = costUpdateTxtFld.getText();
            
            Connection conn = setConnection();
            PreparedStatement stm = conn.prepareStatement("UPDATE registered_projects SET assigned_date = ?, due_date = ?, cost = ? WHERE project_name = ?");
            stm.setString(1, newAssignedDate);
            stm.setString(2, newDueDate);
            stm.setString(3, newCost);
            stm.setString(4, projectName);
            int set = stm.executeUpdate();
            if(set == 1){
                clearTextFields();
                JOptionPane.showMessageDialog(editProjects, "The project has been updated.", "Info", JOptionPane.INFORMATION_MESSAGE);
                generateProjectTable();
            }else{
                JOptionPane.showMessageDialog(editProjects, "The project cannot be updated.", "Error", JOptionPane.ERROR_MESSAGE);

            }
        } catch (SQLException ex) {
            JOptionPane.showMessageDialog(editProjects, "We are experiencing problem while connecting to database. Please try again later.", "Error", JOptionPane.ERROR_MESSAGE);

            Logger.getLogger(ProjectManagement.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
    }//GEN-LAST:event_updateDateBtnActionPerformed

    private void completionYearPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_completionYearPActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_completionYearPActionPerformed

    private void completionMonthPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_completionMonthPActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_completionMonthPActionPerformed

    private void completionDayPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_completionDayPActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_completionDayPActionPerformed

    private void changeStatusBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_changeStatusBtnActionPerformed
        // TODO add your handling code here:
       String projectName = projectDisplayLbl.getText();
       String completionDate = completionYearP.getSelectedItem().toString() + "/" + completionMonthP.getSelectedItem().toString() + "/" + completionDayP.getSelectedItem().toString();
       String completionStatus = completionComboBox.getSelectedItem().toString();
       if(completionStatus.equals("Done")){
           try {
               Connection conn = setConnection();
               PreparedStatement stm = conn.prepareStatement("UPDATE registered_projects SET completion_status = ?, completion_date =?, due_date = ? WHERE project_name = ?");
               stm.setString(1, completionStatus);
               stm.setString(2, completionDate);
               stm.setString(3, "");
               stm.setString(4, projectName);
               int set = stm.executeUpdate();
               if(set == 1){
                clearTextFields();
                JOptionPane.showMessageDialog(editProjects, "The project's status has been updated.", "Info", JOptionPane.INFORMATION_MESSAGE);
                generateProjectTable();
               }
               
           } catch (SQLException ex) {
               JOptionPane.showMessageDialog(editProjects, "The project's cannot be updated", "Error", JOptionPane.ERROR_MESSAGE);
               Logger.getLogger(ProjectManagement.class.getName()).log(Level.SEVERE, null, ex);
           }
           
       } else{
           try {
               Connection conn = setConnection();
               PreparedStatement stm = conn.prepareStatement("UPDATE registered_projects SET completion_status = ? WHERE project_name = ?");
               stm.setString(1, completionStatus);
               stm.setString(2, projectName);
               int set = stm.executeUpdate();
               if(set == 1){
                clearTextFields();
                JOptionPane.showMessageDialog(editProjects, "The project's status has been updated.", "Info", JOptionPane.INFORMATION_MESSAGE);
                generateProjectTable();
               }
           } catch (SQLException ex) {
               JOptionPane.showMessageDialog(editProjects, "The project's cannot be updated", "Error", JOptionPane.ERROR_MESSAGE);
               Logger.getLogger(ProjectManagement.class.getName()).log(Level.SEVERE, null, ex);
           }
       }
    }//GEN-LAST:event_changeStatusBtnActionPerformed

    private void editProjectsTblMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_editProjectsTblMouseClicked
        // TODO add your handling code here:
        this.selectedRow = editProjectsTbl.getSelectedRow();
        String projectName = editProjectsTbl.getValueAt(selectedRow, 0).toString();
        String teamLead = editProjectsTbl.getValueAt(selectedRow, 1).toString();
        String department = editProjectsTbl.getValueAt(selectedRow, 2).toString();
        String assignedDate = editProjectsTbl.getValueAt(selectedRow, 3).toString();
        String dueDate = editProjectsTbl.getValueAt(selectedRow, 4).toString();
        String cost = editProjectsTbl.getValueAt(selectedRow, 7).toString();
        
        String[] aDates = assignedDate.split("/");
        System.out.println(Arrays.toString(aDates));
        assignedYearP.setSelectedItem(aDates[0]);
        assignedMonthP.setSelectedItem(aDates[1]);
        assignedDayP.setSelectedItem(aDates[2]);
        
        if(!dueDate.equals("")){
            String[] dDates = dueDate.split("/");
            dueYearP.setSelectedItem(dDates[0]);
            dueMonthP.setSelectedItem(dDates[1]);
            dueDayP.setSelectedItem(dDates[2]);
        }
        projectDisplayLbl.setText(projectName);
        teamLeadDisplayLbl.setText(teamLead);
        departmentDisplayLbl.setText(department);
        
        costUpdateTxtFld.setText(cost);
        
    }//GEN-LAST:event_editProjectsTblMouseClicked

    private void deleteProjectBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_deleteProjectBtnActionPerformed
        try {
            // TODO add your handling code here:
            String projectName = projectDisplayLbl.getText();
            Connection conn = setConnection();
            PreparedStatement stm = conn.prepareStatement("DELETE FROM registered_projects WHERE project_name =?");
            stm.setString(1, projectName);
            int set = stm.executeUpdate();
            if(set == 1){
                clearTextFields();
                JOptionPane.showMessageDialog(editProjects, "The project has successfully been deleted.", "Info", JOptionPane.INFORMATION_MESSAGE);
                generateProjectTable();
            }
                    } catch (SQLException ex) {
            Logger.getLogger(ProjectManagement.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_deleteProjectBtnActionPerformed

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
    private javax.swing.JLabel assignedDatePLbl;
    private javax.swing.JComboBox<String> assignedDayP;
    private javax.swing.JComboBox<String> assignedDayR;
    private javax.swing.JComboBox<String> assignedMonthP;
    private javax.swing.JComboBox<String> assignedMonthR;
    private javax.swing.JComboBox<String> assignedYearP;
    private javax.swing.JComboBox<String> assignedYearR;
    private javax.swing.JButton backBtn;
    private javax.swing.JButton backForgetBtn;
    private javax.swing.JButton changeStatusBtn;
    private javax.swing.JComboBox<String> completionComboBox;
    private javax.swing.JLabel completionDateP;
    private javax.swing.JComboBox<String> completionDayP;
    private javax.swing.JComboBox<String> completionMonthP;
    private javax.swing.JLabel completionStatusLbl;
    private javax.swing.JComboBox<String> completionYearP;
    private javax.swing.JPanel costRegisterPnl;
    private javax.swing.JTextField costRegisterTxtFld;
    private javax.swing.JPanel costUpdatePnl;
    private javax.swing.JTextField costUpdateTxtFld;
    private javax.swing.JButton deleteProjectBtn;
    private javax.swing.JPanel departRegisterPnl;
    private javax.swing.JTextField departRegisterTxtFld;
    private javax.swing.JLabel departmentDisplay;
    private javax.swing.JLabel departmentDisplayLbl;
    private javax.swing.JLabel departmentLbl;
    private javax.swing.JPanel departmentUpdatePnl;
    private javax.swing.JTextField departmentUpdateTxtFld;
    private javax.swing.JLabel doingLbl;
    private javax.swing.JScrollPane doingPane;
    private javax.swing.JPanel doingPnl;
    private javax.swing.JTable doingTbl;
    private javax.swing.JLabel doneLbl;
    private javax.swing.JScrollPane donePane;
    private javax.swing.JPanel donePnl;
    private javax.swing.JTable doneTbl;
    private javax.swing.JLabel dueDateLbl;
    private javax.swing.JLabel dueDateP;
    private javax.swing.JComboBox<String> dueDayP;
    private javax.swing.JComboBox<String> dueDayR;
    private javax.swing.JComboBox<String> dueMonthP;
    private javax.swing.JComboBox<String> dueMonthR;
    private javax.swing.JComboBox<String> dueYearP;
    private javax.swing.JComboBox<String> dueYearR;
    private javax.swing.JPanel editProjects;
    private javax.swing.JTable editProjectsTbl;
    private javax.swing.JLabel emailDisplay;
    private javax.swing.JPanel emailForgetPnl;
    private javax.swing.JTextField emailForgetTxtFld;
    private javax.swing.JLabel emailLbl;
    private javax.swing.JLabel emailLbl1;
    private javax.swing.JLabel emailLbl2;
    private javax.swing.JPanel emailRegisterPnl;
    private javax.swing.JTextField emailRegisterTxtFld;
    private javax.swing.JPanel emailUpdatePnl;
    private javax.swing.JTextField emailUpdateTxtFld;
    private javax.swing.JLabel forgetInfoPnl;
    private javax.swing.JLabel forgetPassLbl;
    private javax.swing.JPanel forgetPassPnl;
    private javax.swing.JRadioButton forgetPasswordRadio;
    private javax.swing.JPanel homePage;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JScrollBar jScrollBar1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
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
    private javax.swing.JLabel nameLbl;
    private javax.swing.JLabel nameLbl1;
    private javax.swing.JLabel numberDisplay;
    private javax.swing.JPanel numberUpdatePnl;
    private javax.swing.JTextField numberUpdateTxtFld;
    private javax.swing.JPanel passEnterPnl;
    private javax.swing.JPanel passForgetPnl;
    private javax.swing.JPasswordField passForgetTxtFld;
    private javax.swing.JPasswordField passLogInTxtFld;
    private javax.swing.JPanel passPnl;
    private javax.swing.JPanel passRForgetPnl;
    private javax.swing.JPasswordField passRForgetTxtFld;
    private javax.swing.JPanel passRegisterPnl;
    private javax.swing.JTextField passRegisterTxtFld;
    private javax.swing.JPanel profilePage;
    private javax.swing.JLabel profilePhoto;
    private javax.swing.JLabel projectDisplayLbl;
    private javax.swing.JLabel projectLbl;
    private javax.swing.JPanel projectRegisterPnl;
    private javax.swing.JTextField projectRegisterTxtFld;
    private javax.swing.JPanel projectsPage;
    private javax.swing.JButton registerBtn;
    private javax.swing.JButton registerBtnR;
    private javax.swing.JLabel registerLbl;
    private javax.swing.JPanel registerPnl;
    private javax.swing.JLabel registerProjectLbl;
    private javax.swing.JButton submitBtn;
    private javax.swing.JLabel teamLeadDisplayLbl;
    private javax.swing.JLabel teamLeadLbl;
    private javax.swing.JLabel toDoLbl;
    private javax.swing.JScrollPane toDoPane;
    private javax.swing.JPanel toDoPnl;
    private javax.swing.JTable toDoTbl;
    private javax.swing.JButton updateDateBtn;
    private javax.swing.JButton updateInfoBtn;
    private javax.swing.JLabel updateProjectLbl;
    private javax.swing.JPanel userForgetPnl;
    private javax.swing.JTextField userForgetTxtFld;
    private javax.swing.JTextField userLogInTxtFld;
    private javax.swing.JLabel userNameDisplay;
    private javax.swing.JPanel userNamePnl;
    private javax.swing.JPanel userRegisterPnl;
    private javax.swing.JTextField userRegisterTxtFld;
    private javax.swing.JTable usersInfoTbl;
    private javax.swing.JPanel usersPage;
    private javax.swing.JButton validateBtn;
    private javax.swing.JLabel yourNameUpdate;
    // End of variables declaration//GEN-END:variables

    private void clearTextFields(){
        
        //clearing edit projects
        projectDisplayLbl.setText("Choose your project");
        teamLeadDisplayLbl.setText("Team's lead name");
        departmentDisplayLbl.setText("Department's name");
        costUpdateTxtFld.setText("");
        
        //clearing log In Panel
        
        
        //clearing register Panel
        userRegisterTxtFld.setText("");
        passRegisterTxtFld.setText("");
        emailRegisterTxtFld.setText("");
        mobileRegisterTxtFld.setText("");
        departRegisterTxtFld.setText("");
        projectRegisterTxtFld.setText("");
        costRegisterTxtFld.setText("");
        
        //clearing profile update Text field
        emailUpdateTxtFld.setText("");
        numberUpdateTxtFld.setText("");
        departmentUpdateTxtFld.setText("");
        
    }
    
    private void backToLogIn(JPanel panel) {
        //throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
        panel.setVisible(false);
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
    } 
}
