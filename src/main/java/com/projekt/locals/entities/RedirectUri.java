package com.projekt.locals.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "redirect_uris")
@Getter
@Setter
public class RedirectUri {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String uri;

    @ManyToOne
    private Client client;

    public static RedirectUri from(String redirectUris, Client client) {
        var r = new RedirectUri();
        r.setUri(redirectUris);
        r.setClient(client);

        return r;
    }


}
