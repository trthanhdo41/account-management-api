package com.project.note.RestController;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.project.note.DTO.UserDTO;
import com.project.note.Exception.ResourceNotFoundException;
import com.project.note.Model.User;
import com.project.note.Security.JwtAuthenticationResponse;
import com.project.note.Security.JwtTokenProvider;
import com.project.note.Service.Interface.UserService;
import com.project.note.Service.Interface.EmailService;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.util.Utils;
import io.jsonwebtoken.io.IOException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class UserAuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private UserService userService;

    @Autowired
    private EmailService emailService;

    private final DefaultCodeVerifier verifier;

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public UserAuthController() {
        this.verifier = new DefaultCodeVerifier(new dev.samstevens.totp.code.DefaultCodeGenerator(HashingAlgorithm.SHA1), new SystemTimeProvider());
        this.verifier.setAllowedTimePeriodDiscrepancy(1);
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User user) {
        try {
            String message = userService.registerUser(user);
            return ResponseEntity.ok(message);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal Server Error - Lỗi máy chủ nội bộ");
        }
    }

    @GetMapping("/verify-email")
    public ResponseEntity<?> verifyEmailUserAfterRegister(@RequestParam("token") String token) {
        try {
            String message = userService.verifyEmail(token);
            return ResponseEntity.ok(message);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    @PostMapping("/resend-verification-email")
    public ResponseEntity<?> resendVerificationEmail(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        if (username == null || username.trim().isEmpty()) {
            return ResponseEntity.badRequest().body("Username is required");
        }

        try {
            String message = userService.resendVerificationEmail(username);
            return ResponseEntity.ok(message);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(404).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal Server Error - Lỗi máy chủ nội bộ");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody Map<String, String> loginDetails) {
        try {
            String jwt = userService.authenticateUser(
                    loginDetails.get("username"),
                    loginDetails.get("password"),
                    loginDetails.get("totpCode")
            );
            return ResponseEntity.ok(new JwtAuthenticationResponse(jwt));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(401).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error - Lỗi máy chủ nội bộ");
        }
    }

    @GetMapping("/welcome")
    public String welcome() {
        return "Welcome Page";
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User user = userService.findByUsername(userDetails.getUsername());
            UserDTO userDTO = UserDTO.fromUser(user);
            return ResponseEntity.ok(userDTO);
        }
        return ResponseEntity.status(401).body("Unauthorized - Không được phép");
    }


    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public ResponseEntity<?> getAllUsers() {
        List<User> users = userService.getAllUsers();
        List<UserDTO> userDTOs = users.stream()
                .map(UserDTO::fromUser)
                .collect(Collectors.toList());
        return ResponseEntity.ok(userDTOs);
    }


    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/user/{id}")
    public ResponseEntity<?> getUserById(@PathVariable Long id) {
        User user = userService.getUserById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id +
                        " - Người dùng không tìm thấy với id: " + id));
        UserDTO userDTO = UserDTO.fromUser(user);
        return ResponseEntity.ok(userDTO);
    }


    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/user/{id}")
    public ResponseEntity<?> deleteUserById(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.ok().body("User with ID " + id + " has been deleted " +
                "- Người dùng với ID " + id + " đã bị xóa");
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/user/status/{id}")
    public ResponseEntity<?> updateUserStatusById(@PathVariable Long id, @RequestParam Boolean active) {
        try {
            userService.updateUserStatus(id, active);
            String status = active ? "activated - kích hoạt" : "deactivated - vô hiệu hóa";
            return ResponseEntity.ok().body("User with ID " + id + " has been " + status);
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(404).body(e.getMessage());
        }
    }

    @PutMapping("/user/{id}")
    public ResponseEntity<?> updateUserById(@PathVariable Long id, @RequestBody UserDTO userDetails) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            User currentUser = userService.findByUsername(authentication.getName());

            if (!currentUser.getId().equals(id)) {
                return ResponseEntity.status(403).body("Unauthorized to update another user's information " +
                        "- Không được phép cập nhật thông tin của người dùng khác.");
            }

            try {
                User updatedUser = userService.updateUser(id, userDetails.toUser());
                return ResponseEntity.ok().body("User with ID " + id + " has been updated " +
                        "- Người dùng với ID " + id + " đã được cập nhật");
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().body(e.getMessage());
            } catch (ResourceNotFoundException e) {
                return ResponseEntity.status(404).body(e.getMessage());
            }
        }
        return ResponseEntity.status(401).body("Unauthorized - Không được phép");
    }

    @PutMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> passwordDetails) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String username = userDetails.getUsername();
            User user = userService.findByUsername(username);
            String oldPassword = passwordDetails.get("oldPassword");
            String newPassword = passwordDetails.get("newPassword");
            String totpCode = passwordDetails.get("totpCode");

            try {
                String message = userService.changePassword(user.getId(), oldPassword, newPassword, totpCode);
                return ResponseEntity.ok().body(message);
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().body(e.getMessage());
            } catch (ResourceNotFoundException e) {
                return ResponseEntity.status(404).body(e.getMessage());
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal Server Error - Lỗi máy chủ nội bộ");
            }
        }
        return ResponseEntity.status(401).body("Unauthorized - Không được phép");
    }

    @GetMapping("/search")
    public ResponseEntity<?> searchUsersByUsernameOrEmail(@RequestParam(required = false) String username,
                                                          @RequestParam(required = false) String email) {

        if ((username == null || username.trim().isEmpty()) && (email == null || email.trim().isEmpty())) {
            return ResponseEntity.badRequest().body("Username or email must be provided " +
                    "- Phải cung cấp username hoặc email");
        }

        try {
            List<User> users;
            if (username != null && !username.trim().isEmpty()) {
                users = userService.searchUsersByUsername(username);
            } else {
                users = userService.searchUsersByEmail(email);
            }
            List<UserDTO> userDTOs = users.stream()
                    .map(UserDTO::fromUser)
                    .collect(Collectors.toList());
            return ResponseEntity.ok(userDTOs);
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(404).body(e.getMessage());
        }
    }


    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/non-admin")
    public ResponseEntity<?> deleteAllNonAdminUsers() {
        userService.deleteAllNonAdminUsers();
        return ResponseEntity.ok().body("All non-admin users have been deleted " +
                "- Tất cả người dùng không phải quản trị viên đã bị xóa");
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/inactive")
    public ResponseEntity<?> deleteInactiveUsers() {
        try {
            userService.deleteInactiveUsers();
            return ResponseEntity.ok().body("All inactive users have been deleted - Tất cả người dùng không kích hoạt tài khoản đã bị xóa");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal Server Error - Lỗi máy chủ nội bộ");
        }
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/user/{id}/role")
    public ResponseEntity<?> updateUserRole(@PathVariable Long id, @RequestParam String role) {
        try {
            User updatedUser = userService.updateUserRole(id, role);
            return ResponseEntity.ok().body("User role updated successfully to " + role +
                    " - Vai trò người dùng đã được cập nhật thành công thành " + role);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (ResourceNotFoundException e) {
            return ResponseEntity.status(404).body(e.getMessage());
        }
    }

    @PostMapping("/user/{id}/profile-picture")
    public ResponseEntity<?> uploadProfilePicture(@PathVariable Long id, @RequestParam("file") MultipartFile file) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User currentUser = userService.findByUsername(userDetails.getUsername());

            if (!currentUser.getId().equals(id)) {
                return ResponseEntity.status(403).body("You are not authorized to upload a profile picture for another user " +
                        "- Bạn không có quyền tải lên ảnh đại diện cho người dùng khác.");
            }

            try {
                String fileName = userService.storeProfilePicture(id, file);
                return ResponseEntity.ok().body("Profile picture uploaded successfully " +
                        "- Ảnh đại diện đã được tải lên thành công. File name: " + fileName);
            } catch (IOException e) {
                return ResponseEntity.status(500).body("An error occurred while uploading the profile picture " +
                        "- Đã xảy ra lỗi khi tải lên ảnh đại diện.");
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().body(e.getMessage());
            } catch (ResourceNotFoundException e) {
                return ResponseEntity.status(404).body(e.getMessage());
            }
        }
        return ResponseEntity.status(401).body("Unauthorized - Không được phép");
    }

    @DeleteMapping("/user/{id}/profile-picture")
    public ResponseEntity<?> deleteProfilePicture(@PathVariable Long id) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User currentUser = userService.findByUsername(userDetails.getUsername());

            if (!currentUser.getId().equals(id)) {
                return ResponseEntity.status(403).body("You are not authorized to delete a profile picture for another user " +
                        "- Bạn không có quyền xóa ảnh đại diện cho người dùng khác.");
            }

            try {
                userService.deleteProfilePicture(id);
                return ResponseEntity.ok().body("Profile picture deleted successfully " +
                        "- Ảnh đại diện đã được xóa thành công.");
            } catch (ResourceNotFoundException e) {
                return ResponseEntity.status(404).body(e.getMessage());
            }
        }
        return ResponseEntity.status(401).body("Unauthorized - Không được phép");
    }

    @PostMapping("/forgot-password-email")
    public ResponseEntity<?> forgotPassword(@RequestParam String email) {
        try {
            String message = userService.forgotPasswordUseEmail(email);
            return ResponseEntity.ok(message);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    @PostMapping("/reset-password-email")
    public ResponseEntity<?> resetPassword(@RequestParam("token") String token,
                                           @RequestParam("newPassword") String newPassword) {
        try {
            String message = userService.resetPasswordUseEmail(token, newPassword);
            return ResponseEntity.ok(message);
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        }
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/notify-users")
    public ResponseEntity<?> notifyUsers(@RequestBody Map<String, String> emailDetails) {
        String subject = emailDetails.get("subject");
        String message = emailDetails.get("message");

        try {
            emailService.notifyAllUsers(subject, message);
            return ResponseEntity.ok("Notification emails sent to all users successfully" +
                                           " - Email thông báo được gửi tới tất cả người dùng thành công");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error sending notification emails " +
                                                                                "- Lỗi gửi email thông báo");
        }
    }

    //Tạo mã 2FA tạm thời
    @PostMapping("/generate-2fa")
    public ResponseEntity<?> generateTwoFactorAuthentication(Authentication authentication, HttpServletRequest request) {
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User user = userService.findByUsername(userDetails.getUsername());

            Map<String, String> response = userService.generateTwoFactorAuthentication(user, request);
            return ResponseEntity.ok().body(response);
        }
        return ResponseEntity.status(401).body("Unauthorized - Không được phép");
    }


    //Bật 2FA nếu đã tạo mã
    @PostMapping("/enable-2fa")
    public ResponseEntity<?> enableTwoFactorAuthentication(@RequestBody Map<String, String> request, Authentication authentication, HttpServletRequest httpServletRequest) {
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User user = userService.findByUsername(userDetails.getUsername());

            String totpCode = request.get("totpCode");
            if (totpCode == null || totpCode.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("Mã xác thực không được bỏ trống");
            }

            String response = userService.enableTwoFactorAuthentication(user, totpCode, httpServletRequest);
            if (response.equals("success")) {
                return ResponseEntity.ok().body("Xác minh 2 yếu tố đã được bật thành công");
            } else {
                return ResponseEntity.badRequest().body(response);
            }
        }
        return ResponseEntity.status(401).body("Unauthorized - Không được phép");
    }

    //Tắt 2FA
    @PostMapping("/disable-2fa")
    public ResponseEntity<?> disableTwoFactorAuthentication(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User user = userService.findByUsername(userDetails.getUsername());

            String response = userService.disableTwoFactorAuthentication(user);
            if (response.equals("success")) {
                return ResponseEntity.ok().body("Xác minh 2 yếu tố đã được tắt thành công");
            } else {
                return ResponseEntity.badRequest().body(response);
            }
        }
        return ResponseEntity.status(401).body("Unauthorized - Không được phép");
    }





}
