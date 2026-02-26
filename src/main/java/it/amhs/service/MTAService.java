package it.amhs.service;

import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import it.amhs.compliance.AMHSComplianceValidator;
import it.amhs.domain.AMHSChannel;
import it.amhs.domain.AMHSMessage;
import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;
import it.amhs.repository.AMHSMessageRepository;

@Service
public class MTAService {

    private final AMHSMessageRepository amhsMessagesRepository;
    private final AMHSComplianceValidator complianceValidator;
    private final AMHSChannelService channelService;

    public MTAService(
        AMHSMessageRepository amhsMessagesRepository,
        AMHSComplianceValidator complianceValidator,
        AMHSChannelService channelService
    ) {
        this.amhsMessagesRepository = amhsMessagesRepository;
        this.complianceValidator = complianceValidator;
        this.channelService = channelService;
    }

    public AMHSMessage storeMessage(
        String from,
        String to,
        String body,
        String messageId,
        AMHSProfile profile,
        AMHSPriority priority,
        String subject,
        String channelName,
        String certificateCn,
        String certificateOu
    ) {
        complianceValidator.validate(from, to, body, profile);
        AMHSChannel channel = channelService.requireEnabledChannel(channelName);
        complianceValidator.validateCertificateIdentity(channel, certificateCn, certificateOu);

        AMHSMessage message = new AMHSMessage();
        message.setMessageId(resolveMessageId(messageId));
        message.setSender(normalizeUpper(from));
        message.setRecipient(normalizeUpper(to));
        message.setBody(normalize(body));
        message.setProfile(profile);
        message.setPriority(priority == null ? AMHSPriority.GG : priority);
        message.setSubject(normalize(subject));
        message.setChannelName(channel.getName());
        message.setCertificateCn(normalize(certificateCn));
        message.setCertificateOu(normalize(certificateOu));
        return amhsMessagesRepository.save(message);
    }

    public List<AMHSMessage> findAll() {
        return amhsMessagesRepository.findAll();
    }

    private String resolveMessageId(String messageId) {
        return StringUtils.hasText(messageId) ? messageId.trim() : UUID.randomUUID().toString();
    }

    private String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }

    private String normalizeUpper(String value) {
        return normalize(value).toUpperCase();
    }
}