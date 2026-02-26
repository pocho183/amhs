package it.amhs.repository;


import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import it.amhs.domain.AMHSChannel;

@Repository
public interface AMHSChannelRepository extends JpaRepository<AMHSChannel, Long> {
    Optional<AMHSChannel> findByNameIgnoreCase(String name);
}
