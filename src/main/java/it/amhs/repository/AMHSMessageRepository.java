package it.amhs.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import it.amhs.domain.AMHSMessage;

@Repository
public interface AMHSMessageRepository extends JpaRepository<AMHSMessage, Long> {

	Optional<AMHSMessage> findByMessageId(String messageId);
	
}
