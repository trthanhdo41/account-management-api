package com.project.note.Service.Implement;

import com.project.note.Model.User;
import com.project.note.Repository.UserRepository;
import com.project.note.Service.Interface.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class EmailServiceImpl implements EmailService {

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private UserRepository userRepository;

    @Override
    public void sendEmail(String to, String subject, String text) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text);
        mailSender.send(message);
    }

    @Override
    public void notifyAllUsers(String subject, String message) {
        List<User> users = userRepository.findAll();
        for (User user : users) {
            sendEmail(user.getEmail(), subject, message);
        }
    }
}
