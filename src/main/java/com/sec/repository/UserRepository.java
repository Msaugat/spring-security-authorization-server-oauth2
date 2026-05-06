package com.sec.repository;


import com.sec.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    Optional<User> findUserByEmail(String username);

    @Query(
            nativeQuery = true,
            value = """
                    SELECT * FROM users u WHERE u.username = :username OR u.email = :username;
                    """
    )
    Optional<User> findUserByEmailOrUsername(@Param("username") String username);

    boolean existsByUsername(String username);
}
