package com.project.note.Model;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;

@Entity
@Table(name = "users")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "fullname", nullable = false)
    private String fullName;

    @Column(name = "danhxung", nullable = false)
    private String title;

    @Column(name = "email", unique = true, nullable = false)
    private String email;

    @Column(name = "username", unique = true, nullable = false)
    private String username;

    @Column(name = "pw", nullable = false)
    private String password;

    @Column(name = "active")
    private int active;

    @Column(name = "role", nullable = false)
    private String role;

    @Column(name = "registration_time", nullable = false)
    private LocalDateTime registrationTime;

    @Column(name = "profile_picture")
    private String profilePicture;

    @Column(name = "email_verified")
    private boolean emailVerified = false;

    @Column(name = "phone_number", nullable = true)
    private String phoneNumber;

    @Column(name = "totp_secret", nullable = true)
    private String totpSecret;

    // Method to return authorities based on the role
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority(role));
    }

    public User(String fullName, String title, String email, String username, String password, int active, String role, LocalDateTime registrationTime, String phoneNumber) {
        this.fullName = fullName;
        this.title = title;
        this.email = email;
        this.username = username;
        this.password = password;
        this.active = active;
        this.role = role;
        this.registrationTime = registrationTime;
        this.phoneNumber = phoneNumber;
    }
}