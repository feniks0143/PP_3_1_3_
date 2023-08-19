package ru.kata.spring.boot_security.demo.service;

import ru.kata.spring.boot_security.demo.model.User;

import java.util.List;

public interface UserService {

    User findById(Long id);

    List<User> findAll();

    void saveUser(User user, String[] role);

    void delete(Long id);

    void update(User user, Long id, String[] role);

}
