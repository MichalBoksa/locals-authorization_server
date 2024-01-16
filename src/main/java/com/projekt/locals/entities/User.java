package com.projekt.locals.entities;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.util.Set;

@Entity
@Table(name="users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private int id;

    private String name;
    private String email;
    private String password;
    @Column(name="phone_number")
    private String phoneNumber;
    @Column(name="is_guide")
    private boolean isGuide;
    @Column(name="image_uri")
    private String imageUri;


    @ManyToMany(cascade = CascadeType.ALL,fetch = FetchType.EAGER)
    @JsonBackReference
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles;

    public User(String username, String password) {
        this.email = username;
        this.password = password;
    }


}
