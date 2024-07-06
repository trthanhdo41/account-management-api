package com.project.note.Service.Interface;

public interface EmailService {
    void sendEmail(String to, String subject, String text);
    void notifyAllUsers(String subject, String message);
}
