package app.authorizedserverjpa.domain;

import jakarta.persistence.*;
import lombok.Data;

import java.util.List;

@Data
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String email;

    private String password;

    private String name;

    private Boolean isEnabled;

    @ManyToMany(fetch = FetchType.EAGER)
    List<Role> roles;
}
