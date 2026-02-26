package it.amhs.service;

import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import it.amhs.compliance.AMHSComplianceValidator;
import it.amhs.domain.AMHSMessage;
import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;
import it.amhs.repository.AMHSMessageRepository;

@Service
public class MTAService {

    private final AMHSMessageRepository amhsMessagesRepository;
    private final AMHSComplianceValidator complianceValidator;

    public MTAService(AMHSMessageRepository amhsMessagesRepository, AMHSComplianceValidator complianceValidator) {
        this.amhsMessagesRepository = amhsMessagesRepository;
        this.complianceValidator = complianceValidator;
    }

    public AMHSMessage storeMessage(
        String from,
        String to,
        String body,
        String messageId,
        AMHSProfile profile,
        AMHSPriority priority,
        String subject
    ) {
        complianceValidator.validate(from, to, body, profile);

        AMHSMessage message = new AMHSMessage();
        message.setMessageId(resolveMessageId(messageId));
        message.setSender(normalizeUpper(from));
        message.setRecipient(normalizeUpper(to));
        message.setBody(normalize(body));
        message.setProfile(profile);
        message.setPriority(priority == null ? AMHSPriority.GG : priority);
        message.setSubject(normalize(subject));
        return amhsMessagesRepository.save(message);
    }

    public List<AMHSMessage> findAll() {
        return amhsMessagesRepository.findAll();
    }

    private String resolveMessageId(String messageId) {
        return StringUtils.hasText(messageId) ? messageId.trim() : UUID.randomUUID().toString();
    }

	
    private String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim() : "";
    }

    private String normalizeUpper(String value) {
        return normalize(value).toUpperCase();
    }
}