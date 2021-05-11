package service;

import model.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import repository.IUserRepo;

import java.util.ArrayList;
import java.util.List;

@Service
public class AppUserService implements UserDetailsService {
    @Autowired
    IUserRepo iUserRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = this.iUserRepo.findByUsername(username);
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(user.getRoll());

        UserDetails userDetails = new User(
                user.getUsername(),
                user.getPassword(),
                authorities
        );

        return userDetails;
    }
}
