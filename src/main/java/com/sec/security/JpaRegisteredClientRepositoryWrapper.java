package com.sec.security;


import com.sec.entity.RegisteredClientEntity;
import com.sec.repository.JpaRegisteredClientRepository;
import com.sec.security.jpa.JpaConverters;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Transactional
public class JpaRegisteredClientRepositoryWrapper implements RegisteredClientRepository {

    private final JpaRegisteredClientRepository registeredClientRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        this.registeredClientRepository.save(toEntity(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) {
        return this.registeredClientRepository.findById(id)
                .map(this::toObject)
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return this.registeredClientRepository.findByClientId(clientId)
                .map(this::toObject)
                .orElse(null);
    }

    private RegisteredClientEntity toEntity(RegisteredClient client) {
        return JpaConverters.toEntity(client);
    }

    private RegisteredClient toObject(RegisteredClientEntity entity) {
        return JpaConverters.toRegisteredClient(entity);
    }
}
