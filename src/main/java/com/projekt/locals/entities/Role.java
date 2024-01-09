package com.projekt.locals.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

@Entity
@Table(name="roles")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="role_id")
    private int id;
    private String name;

    @ManyToMany(mappedBy = "roles")
    private Set<User> users;

    public Role(int id, String name) {
        this.id = id;
        this.name = name;
    }
}
