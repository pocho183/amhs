package it.amhs.repository;

import java.util.Date;
import java.util.Optional;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import it.amhs.domain.AMHSMessage;
import it.amhs.domain.AMHSProfile;

@Repository
public interface AMHSMessageRepository extends JpaRepository<AMHSMessage, Long> {

	Optional<AMHSMessage> findByMessageId(String messageId);

	List<AMHSMessage> findByChannelNameIgnoreCase(String channelName);

	List<AMHSMessage> findByProfile(AMHSProfile profile);

	List<AMHSMessage> findByChannelNameIgnoreCaseAndProfile(String channelName, AMHSProfile profile);

	long deleteByReceivedAtBefore(Date cutoff);

}
