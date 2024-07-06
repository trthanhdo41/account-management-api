package com.project.note.Service.Interface;

import com.project.note.Model.User;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public interface UserService {
    List<User> getAllUsers();
    Optional<User> getUserById(Long id);
    User createUser(User user);
    void deleteUser(Long id);
    User updateUser(Long id, User userDetails);
    List<User> searchUsersByUsername(String username);
    List<User> searchUsersByEmail(String email);
    public String changePassword(Long id, String oldPassword, String newPassword, String totpCode);
    void updateUserStatus(Long id, Boolean active);
    User findByUsername(String username);
    void save(User user);
    void deleteAllNonAdminUsers();
    void deleteInactiveUsers();
    User updateUserRole(Long id, String role);
    String storeProfilePicture(Long id, MultipartFile file);
    void deleteProfilePicture(Long id);
    ByteArrayInputStream exportUserData();
    User findByEmail(String email);
    String registerUser(User user);
    String authenticateUser(String username, String password, String totpCode);
    String forgotPasswordUseEmail(String email);
    String resetPasswordUseEmail(String token, String newPassword);
    String verifyEmail(String token);
    String resendVerificationEmail(String username);
    UserDetails loadUserByUsername(String username);
    Map<String, String> generateTwoFactorAuthentication(User user, HttpServletRequest request);
    String enableTwoFactorAuthentication(User user, String totpCode, HttpServletRequest httpServletRequest);
    String disableTwoFactorAuthentication(User user);
}
