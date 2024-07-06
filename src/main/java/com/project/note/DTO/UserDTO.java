package com.project.note.DTO;

import com.project.note.Model.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@AllArgsConstructor
@Getter
@Setter
public class UserDTO {
    private Long id;
    private String fullName;
    private String title;
    private String email;
    private String username;
    private String active;
    private String role;
    private String registrationTime;
    private String profilePicture;
    private String phoneNumber;
    private String totpSecret;

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static String formatDateTime(LocalDateTime dateTime) {
        return dateTime != null ? dateTime.format(formatter) : null;
    }

    public static UserDTO fromUser(User user) {
        return new UserDTO(
                user.getId(),
                user.getFullName(),
                user.getTitle().equals("Mr") ? "Ông" : "Bà",
                user.getEmail(),
                user.getUsername(),
                user.getActive() == 1 ? "Đã kích hoạt" : "Chưa kích hoạt",
                user.getRole().equals("ROLE_ADMIN") ? "ADMIN" : "Thành viên thường",
                formatDateTime(user.getRegistrationTime()),
                user.getProfilePicture() != null ? user.getProfilePicture() : "Chưa có ảnh",
                user.getPhoneNumber(),
                user.getTotpSecret() != null ? "Xác thực 2FA đã bật" : "Xác thực 2FA chưa bật"
        );
    }

    public User toUser() {
        User user = new User();
        user.setId(this.id);
        user.setFullName(this.fullName);
        user.setTitle(this.title);
        user.setEmail(this.email);
        user.setUsername(this.username);
        user.setActive((this.active != null && this.active.equals("Đã kích hoạt")) ? 1 : 0);
        user.setRole((this.role != null && this.role.equals("ADMIN")) ? "ROLE_ADMIN" : "ROLE_USER");
        if (this.registrationTime != null) {
            user.setRegistrationTime(LocalDateTime.parse(this.registrationTime, formatter));
        }
        user.setProfilePicture(this.profilePicture);
        user.setPhoneNumber(this.phoneNumber);
        user.setTotpSecret(this.totpSecret != null && this.totpSecret.equals("Xác thực 2FA đã bật") ? "secret_value_placeholder" : null);
        return user;
    }

}
