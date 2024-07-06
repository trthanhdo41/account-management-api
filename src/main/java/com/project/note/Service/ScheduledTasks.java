package com.project.note.Service;

import com.project.note.Repository.PasswordResetTokenRepository;
import com.project.note.Repository.EmailVerificationTokenRepository;
import com.project.note.Repository.UserRepository;
import com.project.note.Model.EmailVerificationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class ScheduledTasks {

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    private EmailVerificationTokenRepository emailVerificationTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Scheduled(fixedRate = 180000) // Mỗi 3 phút (180000 ms)
    public void deleteExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        passwordResetTokenRepository.deleteExpiredTokens(now);
        emailVerificationTokenRepository.deleteExpiredTokens(now);
        deleteUnverifiedUsers(now);
    }

    private void deleteUnverifiedUsers(LocalDateTime now) {
        List<EmailVerificationToken> expiredTokens = emailVerificationTokenRepository.findByExpiryDateBefore(now);

        for (EmailVerificationToken token : expiredTokens) {
            userRepository.delete(token.getUser());
            emailVerificationTokenRepository.delete(token);
        }
    }
}
