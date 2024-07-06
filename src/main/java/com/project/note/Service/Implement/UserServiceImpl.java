package com.project.note.Service.Implement;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.project.note.Exception.ResourceNotFoundException;
import com.project.note.Model.EmailVerificationToken;
import com.project.note.Model.PasswordResetToken;
import com.project.note.Model.User;
import com.project.note.Repository.EmailVerificationTokenRepository;
import com.project.note.Repository.PasswordResetTokenRepository;
import com.project.note.Repository.UserRepository;
import com.project.note.Security.JwtTokenProvider;
import com.project.note.Service.Interface.UserService;
import com.project.note.Service.Interface.EmailService;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.io.ByteArrayOutputStream;

@Service
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;
    private final JwtTokenProvider tokenProvider;
    private final DefaultCodeVerifier verifier;

    @Autowired
    public UserServiceImpl(UserRepository userRepository,
                           @Lazy PasswordEncoder passwordEncoder,
                           PasswordResetTokenRepository passwordResetTokenRepository,
                           EmailVerificationTokenRepository emailVerificationTokenRepository,
                           @Lazy AuthenticationManager authenticationManager,
                           EmailService emailService,
                           JwtTokenProvider tokenProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.emailVerificationTokenRepository = emailVerificationTokenRepository;
        this.authenticationManager = authenticationManager;
        this.emailService = emailService;
        this.tokenProvider = tokenProvider;

        CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1);
        this.verifier = new DefaultCodeVerifier(codeGenerator, new SystemTimeProvider());
        this.verifier.setAllowedTimePeriodDiscrepancy(1);
    }


    private static final String PASSWORD_PATTERN = "^(?=.*[!@#$%^&*(),.?\":{}|<>]).{6,}$";
    private static final String EMAIL_PATTERN = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,6}$";

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public Optional<User> getUserById(Long id) {
        Optional<User> user = userRepository.findById(id);
        return user;
    }

    @Override
    @Transactional
    public User createUser(User user) {
        if (user.getFullName() == null || user.getFullName().trim().isEmpty()) {
            throw new IllegalArgumentException("Họ và tên không được bỏ trống");
        }
        if (user.getTitle() == null || user.getTitle().trim().isEmpty()) {
            throw new IllegalArgumentException("Chức danh không được bỏ trống");
        }
        if (user.getEmail() == null || user.getEmail().trim().isEmpty()) {
            throw new IllegalArgumentException("Email không được bỏ trống");
        }
        if (!Pattern.matches(EMAIL_PATTERN, user.getEmail())) {
            throw new IllegalArgumentException("Định dạng email không hợp lệ");
        }
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Tên đăng nhập đã tồn tại");
        }
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email đã tồn tại");
        }
        if (!Pattern.matches(PASSWORD_PATTERN, user.getPassword())) {
            throw new IllegalArgumentException("Mật khẩu phải chứa ít nhất 6 ký tự và 1 ký tự đặc biệt");
        }
        if (user.getPhoneNumber() == null || user.getPhoneNumber().trim().isEmpty()) {
            throw new IllegalArgumentException("Số điện thoại không được bỏ trống");
        }
        if (!Pattern.matches("^\\d{10}$", user.getPhoneNumber())) {
            throw new IllegalArgumentException("Số điện thoại không hợp lệ");
        }
        if (!userRepository.findByPhoneNumber(user.getPhoneNumber()).isEmpty()) {
            throw new IllegalArgumentException("Số điện thoại đã tồn tại");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole("ROLE_USER");
        user.setRegistrationTime(LocalDateTime.now());
        user.setActive(0); // Chưa kích hoạt
        user.setEmailVerified(false);
        user.setTotpSecret(null);
        return userRepository.save(user);
    }

    @Override
    @Transactional
    public String registerUser(User user) {
        if (user.getPassword() == null || !user.getPassword().matches(PASSWORD_PATTERN)) {
            throw new IllegalArgumentException("Password must contain at least one special character " +
                    "- Mật khẩu phải chứa ít nhất một ký tự đặc biệt.");
        }

        User createdUser = createUser(user);

        String token = UUID.randomUUID().toString();
        EmailVerificationToken emailVerificationToken = new EmailVerificationToken();
        emailVerificationToken.setToken(token);
        emailVerificationToken.setUser(createdUser);
        emailVerificationToken.setExpiryDate(LocalDateTime.now().plusMinutes(3)); // Hết hạn sau 3 phút

        emailVerificationTokenRepository.save(emailVerificationToken);

        String verificationUrl = "http://localhost:8080/api/auth/verify-email?token=" + token;
        emailService.sendEmail(user.getEmail(), "Email Verification (Kích hoạt tài khoản Note Myself)",
                "Click the link to verify your email (Bấm vào đây để xác minh email của bạn): " + verificationUrl);

        return "Đăng ký tài khoản thành công, vui lòng xác minh email " + user.getEmail() + " để kích hoạt tài khoản - thời hạn trong 3 phút";
    }

    @Override
    @Transactional
    public String authenticateUser(String username, String password, String totpCode) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
        } catch (Exception e) {
            throw new IllegalArgumentException("Tên đăng nhập hoặc mật khẩu không đúng");
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Tên đăng nhập hoặc mật khẩu không đúng"));

        if (user.getActive() != 1) {
            throw new IllegalArgumentException("Tài khoản chưa được kích hoạt");
        }

        // Kiểm tra nếu tài khoản đã bật xác minh 2 yếu tố
        if (user.getTotpSecret() != null) {
            // Verify the TOTP code
            if (totpCode == null || !verifier.isValidCode(user.getTotpSecret(), totpCode)) {
                throw new IllegalArgumentException("Mã xác thực 2 yếu tố không đúng");
            }
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        return tokenProvider.generateToken(authentication);
    }

    @Transactional
    public String verifyEmail(String token) {
        EmailVerificationToken emailVerificationToken = emailVerificationTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token - Hết hạn"));

        User user = emailVerificationToken.getUser();
        user.setEmailVerified(true);
        user.setActive(1); // Kích hoạt tài khoản
        userRepository.save(user);

        emailVerificationTokenRepository.delete(emailVerificationToken);

        return "Email has been verified successfully";
    }

    @Override
    @Transactional
    public String resendVerificationEmail(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with username - " + username));

        if (user.getActive() == 1) {
            return "Tài khoản đã được kích hoạt";
        }

        // Kiểm tra nếu đã có mã xác minh chưa hết hạn
        List<EmailVerificationToken> existingTokens = emailVerificationTokenRepository.findByUser(user);
        for (EmailVerificationToken token : existingTokens) {
            if (token.getExpiryDate().isAfter(LocalDateTime.now())) {
                throw new IllegalArgumentException("Email xác minh đã được gửi, vui lòng thử lại sau 3 phút");
            }
        }

        String token = UUID.randomUUID().toString();
        EmailVerificationToken emailVerificationToken = new EmailVerificationToken();
        emailVerificationToken.setToken(token);
        emailVerificationToken.setUser(user);
        emailVerificationToken.setExpiryDate(LocalDateTime.now().plusMinutes(3)); // Hết hạn sau 3 phút

        emailVerificationTokenRepository.save(emailVerificationToken);

        String verificationUrl = "http://localhost:8080/api/auth/verify-email?token=" + token;
        emailService.sendEmail(user.getEmail(), "Email Verification (Kích hoạt tài khoản Note Myself)",
                "Click the link to verify your email (Bấm vào đây để xác minh email của bạn): " + verificationUrl);

        return "Đã gửi lại email xác minh cho " + user.getEmail() + ", vui lòng xác minh email của bạn để kích hoạt tài khoản - thời hạn trong 3 phút";
    }


    @Override
    @Transactional
    public User updateUser(Long id, User userDetails) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User with ID - " + id + " not found"));

        if (userDetails.getFullName() != null && !userDetails.getFullName().trim().isEmpty()) {
            user.setFullName(userDetails.getFullName());
        }

        if (userDetails.getTitle() != null && !userDetails.getTitle().trim().isEmpty()) {
            if (!userDetails.getTitle().equals("Mr") && !userDetails.getTitle().equals("Ms")) {
                throw new IllegalArgumentException("Chức danh phải là Mr hoặc Ms");
            }
            user.setTitle(userDetails.getTitle());
        }

        if (userDetails.getEmail() != null && !userDetails.getEmail().trim().isEmpty()) {
            if (!Pattern.matches(EMAIL_PATTERN, userDetails.getEmail())) {
                throw new IllegalArgumentException("Định dạng email không hợp lệ");
            }
            Optional<User> existingUserWithEmail = userRepository.findByEmail(userDetails.getEmail());
            if (existingUserWithEmail.isPresent() && !existingUserWithEmail.get().getId().equals(id)) {
                throw new IllegalArgumentException("Email " + userDetails.getEmail() + " đã tồn tại trong hệ thống");
            }
            user.setEmail(userDetails.getEmail());
        }

        if (userDetails.getPhoneNumber() != null && !userDetails.getPhoneNumber().trim().isEmpty()) {
            if (!Pattern.matches("^\\d{10}$", userDetails.getPhoneNumber())) {
                throw new IllegalArgumentException("Số điện thoại không hợp lệ");
            }
            List<User> existingUsersWithPhoneNumber = userRepository.findByPhoneNumber(userDetails.getPhoneNumber());
            if (existingUsersWithPhoneNumber.stream().anyMatch(existingUser -> !existingUser.getId().equals(id))) {
                throw new IllegalArgumentException("Số điện thoại " + userDetails.getPhoneNumber() + " đã tồn tại trong hệ thống");
            }
            user.setPhoneNumber(userDetails.getPhoneNumber());
        }

        return userRepository.saveAndFlush(user);
    }

    @Override
    @Transactional
    public void deleteUser(Long id) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User currentUser = findByUsername(userDetails.getUsername());

            if (currentUser.getId().equals(id)) {
                throw new IllegalArgumentException("You cannot delete your own account - Bạn không thể xóa tài khoản của chính mình");
            }
        }

        if (!userRepository.existsById(id)) {
            throw new ResourceNotFoundException("User with ID: " + id + " not found");
        }
        userRepository.deleteById(id);
    }

    @Override
    public List<User> searchUsersByUsername(String username) {
        List<User> users = userRepository.findByUsernameContainingIgnoreCase(username);
        if (users.isEmpty()) {
            throw new ResourceNotFoundException("No users found with username: " + username);
        }
        return users;
    }

    @Override
    public List<User> searchUsersByEmail(String email) {
        List<User> users = userRepository.findByEmailContainingIgnoreCase(email);
        if (users.isEmpty()) {
            throw new ResourceNotFoundException("No users found with email: " + email);
        }
        return users;
    }

    @Transactional
    public String changePassword(Long id, String oldPassword, String newPassword, String totpCode) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User với ID - " + id + " không tìm thấy"));

        if (oldPassword == null || oldPassword.trim().isEmpty()) {
            throw new IllegalArgumentException("Mật khẩu cũ không được bỏ trống");
        }

        if (newPassword == null || newPassword.trim().isEmpty()) {
            throw new IllegalArgumentException("Mật khẩu mới không được bỏ trống");
        }

        if (!Pattern.matches(PASSWORD_PATTERN, newPassword)) {
            throw new IllegalArgumentException("Mật khẩu tối thiểu 6 kí tự và 1 ký tự đặc biệt");
        }

        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new IllegalArgumentException("Mật khẩu cũ không đúng");
        }

        // Kiểm tra nếu tài khoản đã bật xác minh 2 yếu tố
        if (user.getTotpSecret() != null) {
            // Verify the TOTP code
            if (totpCode == null || !verifier.isValidCode(user.getTotpSecret(), totpCode)) {
                throw new IllegalArgumentException("Mã xác thực không đúng");
            }
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.saveAndFlush(user);

        return "Mật khẩu của tài khoản " + user.getUsername() + " đã được thay đổi thành công";
    }

    @Override
    @Transactional
    public void updateUserStatus(Long id, Boolean active) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            User currentUser = userRepository.findByUsername(authentication.getName())
                    .orElseThrow(() -> new ResourceNotFoundException("Current user not found"));

            if (currentUser.getId().equals(id)) {
                throw new IllegalArgumentException("Cannot change the status of yourself " +
                                                   "- Không thể thay đổi trạng thái của chính bản thân");
            }
        }

        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User with ID - " + id + " not found"));
        user.setActive(active ? 1 : 0);  // Giả sử `active` là trường kiểu `int` với 1 là kích hoạt và 0 là khóa
        userRepository.saveAndFlush(user);
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), user.getAuthorities());
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with username - " + username));
    }

    @Override
    @Transactional
    public void save(User user) {
        userRepository.save(user);
    }

    @Override
    @Transactional
    public void deleteAllNonAdminUsers() {
        List<User> nonAdminUsers = userRepository.findAll().stream()
                .filter(user -> !user.getRole().equals("ROLE_ADMIN"))
                .collect(Collectors.toList());

        userRepository.deleteAll(nonAdminUsers);
    }

    @Override
    @Transactional
    public void deleteInactiveUsers() {
        List<User> inactiveUsers = userRepository.findByActive(0);
        userRepository.deleteAll(inactiveUsers);
    }

    @Override
    @Transactional
    public User updateUserRole(Long id, String role) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            User currentUser = userRepository.findByUsername(authentication.getName())
                    .orElseThrow(() -> new ResourceNotFoundException("Current user not found"));

            if (currentUser.getId().equals(id)) {
                throw new IllegalArgumentException("Cannot change the role of yourself " +
                                                   "- Không thể thay đổi vai trò của chính bản thân");
            }
        }

        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User with ID - " + id + " not found " +
                                                                 "- Người dùng với ID - " + id + " không tìm thấy"));

        if (!role.equals("ROLE_ADMIN") && !role.equals("ROLE_USER")) {
            throw new IllegalArgumentException("Invalid role - Vai trò không hợp lệ");
        }

        user.setRole(role);
        return userRepository.saveAndFlush(user);
    }


    @Override
    @Transactional
    public String storeProfilePicture(Long id, MultipartFile file) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User with ID - " + id + " not found"));

        String fileType = file.getContentType();
        if (fileType == null || !(fileType.equals("image/jpeg") || fileType.equals("image/png"))) {
            throw new IllegalArgumentException("Invalid file type - Định dạng file không hợp lệ. Chỉ hỗ trợ JPEG và PNG.");
        }

        String fileName = UUID.randomUUID().toString() + "_" + file.getOriginalFilename();
        Path filePath = Paths.get("uploads/profile_pictures", fileName);

        try {
            Files.createDirectories(filePath.getParent());
            Files.copy(file.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);

            user.setProfilePicture("/profile_pictures/" + fileName);
            userRepository.saveAndFlush(user);

            return "/profile_pictures/" + fileName;
        } catch (IOException e) {
            throw new RuntimeException("Failed to store profile picture - Không thể lưu ảnh đại diện", e);
        }
    }

    @Override
    @Transactional
    public void deleteProfilePicture(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User with ID - " + id + " not found"));

        String profilePicture = user.getProfilePicture();
        if (profilePicture != null) {
            Path filePath = Paths.get("uploads/profile_pictures", profilePicture);
            try {
                Files.deleteIfExists(filePath);
                user.setProfilePicture(null);
                userRepository.saveAndFlush(user);
            } catch (IOException e) {
                throw new RuntimeException("Failed to delete profile picture - Không thể xóa ảnh đại diện", e);
            }
        } else {
            throw new IllegalArgumentException("No profile picture to delete - Không có ảnh đại diện để xóa");
        }
    }

    @Override
    public ByteArrayInputStream exportUserData() {
        String[] columns = {"Id", "Full Name", "Title", "Email", "Username", "Active", "Role", "Registration Time", "Profile Picture", "Phone Number", "2FA Status"};
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        try (Workbook workbook = new XSSFWorkbook(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            Sheet sheet = workbook.createSheet("Users");

            Font headerFont = workbook.createFont();
            headerFont.setBold(true);
            headerFont.setColor(IndexedColors.BLUE.getIndex());

            CellStyle headerCellStyle = workbook.createCellStyle();
            headerCellStyle.setFont(headerFont);

            CellStyle greenCellStyle = workbook.createCellStyle();
            Font greenFont = workbook.createFont();
            greenFont.setColor(IndexedColors.GREEN.getIndex());
            greenCellStyle.setFont(greenFont);

            CellStyle redCellStyle = workbook.createCellStyle();
            Font redFont = workbook.createFont();
            redFont.setColor(IndexedColors.RED.getIndex());
            redCellStyle.setFont(redFont);

            Row headerRow = sheet.createRow(0);

            for (int i = 0; i < columns.length; i++) {
                Cell cell = headerRow.createCell(i);
                cell.setCellValue(columns[i]);
                cell.setCellStyle(headerCellStyle);
            }

            List<User> users = userRepository.findAll();
            int rowIdx = 1;
            for (User user : users) {
                Row row = sheet.createRow(rowIdx++);

                row.createCell(0).setCellValue(user.getId());
                row.createCell(1).setCellValue(user.getFullName());
                row.createCell(2).setCellValue(user.getTitle().equals("Mr") ? "Ông" : "Bà");
                row.createCell(3).setCellValue(user.getEmail());
                row.createCell(4).setCellValue(user.getUsername());

                Cell activeCell = row.createCell(5);
                if (user.getActive() == 1) {
                    activeCell.setCellValue("✔");
                    activeCell.setCellStyle(greenCellStyle);
                } else {
                    activeCell.setCellValue("✘");
                    activeCell.setCellStyle(redCellStyle);
                }

                row.createCell(6).setCellValue(user.getRole().equals("ROLE_ADMIN") ? "ADMIN" : "Thành viên thường");
                row.createCell(7).setCellValue(user.getRegistrationTime().format(formatter));
                row.createCell(8).setCellValue(user.getProfilePicture() != null ? user.getProfilePicture() : "Chưa có ảnh");
                row.createCell(9).setCellValue(user.getPhoneNumber());

                Cell twoFACell = row.createCell(10);
                if (user.getTotpSecret() != null) {
                    twoFACell.setCellValue("✔");
                    twoFACell.setCellStyle(greenCellStyle);
                } else {
                    twoFACell.setCellValue("✘");
                    twoFACell.setCellStyle(redCellStyle);
                }
            }

            // Auto-size columns
            for (int i = 0; i < columns.length; i++) {
                sheet.autoSizeColumn(i);
            }

            workbook.write(out);
            return new ByteArrayInputStream(out.toByteArray());

        } catch (IOException e) {
            throw new RuntimeException("Failed to export user data to Excel file", e);
        }
    }

    @Override
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Email not found - Email không tồn tại, không tìm thấy"));
    }

    @Transactional
    public String forgotPasswordUseEmail(String email) {
        User user = findByEmail(email);
        if (user == null) {
            throw new ResourceNotFoundException("Email không tồn tại trong hệ thống");
        }

        PasswordResetToken existingToken = passwordResetTokenRepository.findByUser(user);
        if (existingToken != null && existingToken.getExpiryDate().isAfter(LocalDateTime.now())) {
            throw new RuntimeException("Vui lòng thử lại sau 3 phút");
        }

        String token = UUID.randomUUID().toString();
        PasswordResetToken passwordResetToken = new PasswordResetToken();
        passwordResetToken.setToken(token);
        passwordResetToken.setUser(user);
        passwordResetToken.setExpiryDate(LocalDateTime.now().plusMinutes(3));

        try {
            passwordResetTokenRepository.save(passwordResetToken);
        } catch (Exception e) {
            throw new RuntimeException("Vui lòng thử lại sau 3 phút");
        }

        String resetUrl = "http://localhost:8080/api/auth/reset-password?token=" + token;
        emailService.sendEmail(user.getEmail(), "Reset Password (Khôi phục mật khẩu Note Myself)", "Click the link to reset your password "
                + "(Bấm vào đây để thay đổi mật khẩu của bạn): " + resetUrl);

        return "Đã gửi email đặt lại mật khẩu tới " + user.getEmail() + " - thời hạn trong 3 phút";
    }

    @Override
    @Transactional
    public String resetPasswordUseEmail(String token, String newPassword) {
        if (newPassword == null || newPassword.trim().isEmpty()) {
            throw new IllegalArgumentException("Password must not be empty - Mật khẩu không được bỏ trống");
        }

        if (!Pattern.matches(PASSWORD_PATTERN, newPassword)) {
            throw new IllegalArgumentException("Password must contain at least one special character and be at least 6 characters long - Mật khẩu phải chứa ít nhất một ký tự đặc biệt và có ít nhất 6 ký tự");
        }

        PasswordResetToken passwordResetToken = passwordResetTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token - Hết hạn"));

        User user = passwordResetToken.getUser();

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        passwordResetTokenRepository.delete(passwordResetToken);

        return "Password has been reset successfully - Mật khẩu đã được thay đổi thành công";
    }

    @Override
    public Map<String, String> generateTwoFactorAuthentication(User user, HttpServletRequest request) {
        SecretGenerator secretGenerator = new DefaultSecretGenerator();
        String tempSecret = secretGenerator.generate();

        String totpUrl = "otpauth://totp/NoteApp:" + user.getUsername() + "?secret=" + tempSecret + "&issuer=NoteApp";

        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix;
        try {
            bitMatrix = qrCodeWriter.encode(totpUrl, BarcodeFormat.QR_CODE, 200, 200);
        } catch (WriterException e) {
            throw new RuntimeException("Error generating QR code");
        }

        ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
        try {
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);
        } catch (IOException e) {
            throw new RuntimeException("Error writing QR code to stream");
        }

        String qrImage = Base64.getEncoder().encodeToString(pngOutputStream.toByteArray());
        String qrDataUri = "data:image/png;base64," + qrImage;

        Map<String, String> response = new HashMap<>();
        response.put("qrDataUri", qrDataUri);
        response.put("totpSecret", tempSecret);

        request.getSession().setAttribute("tempTotpSecret", tempSecret);

        return response;
    }

    @Override
    public String enableTwoFactorAuthentication(User user, String totpCode, HttpServletRequest httpServletRequest) {
        String tempTotpSecret = (String) httpServletRequest.getSession().getAttribute("tempTotpSecret");
        if (tempTotpSecret == null) {
            return "Không tìm thấy mã TOTP tạm thời";
        }

        if (!verifier.isValidCode(tempTotpSecret, totpCode)) {
            return "Mã xác thực không đúng";
        }

        user.setTotpSecret(tempTotpSecret);
        save(user);

        httpServletRequest.getSession().removeAttribute("tempTotpSecret");

        return "success";
    }

    @Override
    public String disableTwoFactorAuthentication(User user) {
        if (user.getTotpSecret() == null) {
            return "2FA chưa được bật cho tài khoản này";
        }
        user.setTotpSecret(null);
        save(user);
        return "success";
    }

}
