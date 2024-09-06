package app.authorizedserverjpa.service;

import app.authorizedserverjpa.custome.CustomizeUserDetail;
import app.authorizedserverjpa.domain.User;
import app.authorizedserverjpa.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@Transactional
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {


    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        User user = userRepository.findByEmail(email).orElseThrow(()-> new UsernameNotFoundException("user has not " +
                "been found"));

        CustomizeUserDetail customizeUserDetail = new CustomizeUserDetail();
        customizeUserDetail.setUser(user);
        return  customizeUserDetail;
    }

    private Collection<? extends GrantedAuthority> getAuthorities(List<String> roles) {

        List<GrantedAuthority> authorities =  new ArrayList<>();

        for (String role:roles){
            authorities.add(new SimpleGrantedAuthority(role));
        }

        return authorities;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(11) ;
    }
}
