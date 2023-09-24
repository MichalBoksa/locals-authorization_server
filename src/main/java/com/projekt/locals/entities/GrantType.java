package com.projekt.locals.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

@Entity
@Table(name = "grant_types")
@Getter
@Setter
public class GrantType {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column(name = "grant_type")
    private String grantType;

    @ManyToOne
    private Client client;


    public static GrantType from(AuthorizationGrantType authGrantType, Client client) {
        var grantType = new GrantType();

        grantType.setGrantType(authGrantType.getValue());
        grantType.setClient(client);
        return grantType;
    }

}
