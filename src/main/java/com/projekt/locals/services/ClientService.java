package com.projekt.locals.services;

import com.projekt.locals.entities.*;
import com.projekt.locals.repositories.ClientRepository;

import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.stream.Collectors;

@Service
@AllArgsConstructor
@Transactional(readOnly = true)
public class ClientService implements RegisteredClientRepository {

    private final ClientRepository clientRepository;

    @Transactional
    @Override
    public void save(RegisteredClient registeredClient) {
        var client = new Client();

        client.setClientId(registeredClient.getClientId());
        client.setClientSecret(registeredClient.getClientSecret());
        client.setAuthenticationMethods(
                registeredClient.getClientAuthenticationMethods().stream().map(
                        authMethod -> AuthenticationMethod.from(authMethod,client))
                        .collect(Collectors.toList())

        );
        client.setGrantTypes(registeredClient.getAuthorizationGrantTypes().stream().map(
                grantType -> GrantType.from(grantType,client)).collect(Collectors.toList())
        );
        client.setRedirectUris(registeredClient.getRedirectUris().stream().map(
                uri -> RedirectUri.from(uri,client)).collect(Collectors.toList())
        );
        client.setScopes(registeredClient.getScopes().stream().map(
                scope -> Scope.from(scope, client)).collect(Collectors.toList())
        );

        clientRepository.save(client);

    }

    @Override
    public RegisteredClient findById(String id) {
        var client = clientRepository.findById(Integer.parseInt(id));
        return client.map(Client::fromClient)
                .orElseThrow(() -> new RuntimeException("Runtime exception"));
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        var client = clientRepository.findByClientId(clientId);
        return client.map(Client::fromClient)
                .orElseThrow(() -> new RuntimeException("Runtime exception"));
    }
}
