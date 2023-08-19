package ru.kata.spring.boot_security.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.repository.UserRepository;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class UserServiceImp implements UserService {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private final RoleService roleService;



    @Autowired
    public UserServiceImp(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder,
                          RoleService roleService) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.roleService = roleService;
    }

    @Override
    @Transactional(readOnly = true)
    public User findById(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public List<User> findAll() {
        return userRepository.findAll();
    }

    @Override
    @Transactional
//    public void saveUser(@ModelAttribute("user") User user, @RequestParam("role") String[] role) {
//        if (role != null) {
//            Set<Role> roles = new HashSet<>();
//            for(String r: role) {
//                roles.add(roleService.getRoleByName(r));
//            }
//            user.setRoles(roles);
//        }
//        userRepository.save(user);
//        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
//    }
    public void saveUser(@ModelAttribute("user") User user, @RequestParam("role") String[] role) {
        try {
            if (role != null) {
                Set<Role> roles = new HashSet<>();
                for(String r: role) {
                    roles.add(roleService.getRoleByName(r));
                }
                user.setRoles(roles);
            }

            user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
            userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            // Обработка исключения при нарушении уникальности username
            throw new DataIntegrityViolationException("Username is already taken.");
        }
    }

    @Override
    @Transactional
    public void delete(Long id) {
        userRepository.deleteById(id);
    }

    @Override
    public void update(@ModelAttribute("user") User user,@PathVariable("id") Long id,
                       @RequestParam(name = "role", required = false) String[] role) {

        User updateUser = userRepository.findById(id).orElse(null);

        if (role != null) {
            Set<Role> roles = new HashSet<>();
            for(String r: role) {
                roles.add(roleService.getRoleByName(r));
            }
            user.setRoles(roles);
        } else {
            user.setRoles(updateUser.getRoles());
        }

        updateUser.setName(user.getName());
        updateUser.setLastName(user.getLastName());
        updateUser.setAbility(user.getAbility());
        updateUser.setAlias(user.getAlias());
        updateUser.setUsername(user.getUsername());
        updateUser.setRoles(user.getRoles());

        if (user.getPassword() != null) {
            updateUser.setPassword(user.getPassword());
        }

        userRepository.saveAndFlush(updateUser);
    }

}
