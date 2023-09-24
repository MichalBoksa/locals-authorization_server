package com.projekt.locals.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

@Entity
@Table(name="clients")
@Getter
@Setter
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "secret")
    private String clientSecret;

    @OneToMany(mappedBy = "client", fetch = FetchType.EAGER)
    private List<GrantType> grantTypes;

    @OneToMany(mappedBy = "client", fetch = FetchType.EAGER)
    private List<Scope> scopes;

    @OneToMany(mappedBy = "client", fetch = FetchType.EAGER)
    private List<RedirectUri> redirectUris;

    @OneToMany(mappedBy = "client", fetch = FetchType.EAGER)
    private List<AuthenticationMethod> authenticationMethods;


    public static RegisteredClient fromClient(Client client) {
        return RegisteredClient.withId(String.valueOf(client.getId()))
                .clientId(client.getClientId())
                .clientSecret(client.getClientSecret())
                .authorizationGrantTypes(clientAuthenticationGrantTypes(client.getGrantTypes()))
                .clientAuthenticationMethods(clientAuthenticationMethods(client.getAuthenticationMethods()))
                .scopes(clientScopes(client.getScopes()))
                .redirectUris(clientRedirectUris(client.getRedirectUris()))
                .build();

    }
    //TODO check consumer
    private static Consumer<Set<ClientAuthenticationMethod>> clientAuthenticationMethods(List<AuthenticationMethod> authenticationMethods) {
        return s -> {
            for (AuthenticationMethod a: authenticationMethods) {
                s.add(new ClientAuthenticationMethod(a.getAuthenticatedMethod()));
            }
        };
    }

    private static Consumer<Set<AuthorizationGrantType>> clientAuthenticationGrantTypes(List<GrantType> grantTypes) {
        return s -> {
            for (GrantType g: grantTypes) {
                s.add(new AuthorizationGrantType(g.getGrantType()));
            }
        };
    }

    private static Consumer<Set<String>> clientScopes(List<Scope> scopes) {
        return s -> {
            for (Scope scope: scopes) {
                s.add(scope.getScope());
            }
        };
    }

    private static Consumer<Set<String>> clientRedirectUris(List<RedirectUri> redirectUris) {
        return u -> {
            for (RedirectUri uri: redirectUris) {
                u.add(uri.getUri());
            }
        };
    }

}
