package it.amhs.service;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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

    private static final Logger logger = LoggerFactory.getLogger(MTAService.class);

    private final AMHSMessageRepository amhsMessagesRepository;
    private final AMHSComplianceValidator complianceValidator;
    private final AMHSChannelService channelService;
    private final boolean databaseEnabled;

    public MTAService(
        AMHSMessageRepository amhsMessagesRepository,
        AMHSComplianceValidator complianceValidator,
        AMHSChannelService channelService,
        @Value("${amhs.database.enabled:true}") boolean databaseEnabled
    ) {
        this.amhsMessagesRepository = amhsMessagesRepository;
        this.complianceValidator = complianceValidator;
        this.channelService = channelService;
        this.databaseEnabled = databaseEnabled;
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
        String certificateOu,
        Date filingTime
    ) {
        AMHSMessage message = buildBaseMessage(from, to, body, messageId, profile, priority, subject, channelName, certificateCn, certificateOu, filingTime);
        if (!databaseEnabled) {
            logReceivedMessage(message);
            return message;
        }

        complianceValidator.validate(from, to, body, profile);
        AMHSChannel channel = channelService.requireEnabledChannel(channelName);
        complianceValidator.validateCertificateIdentity(channel, certificateCn, certificateOu);
        message.setChannelName(channel.getName());
        return amhsMessagesRepository.save(message);
    }

    public AMHSMessage storeX400Message(
        String from,
        String to,
        String body,
        String messageId,
        AMHSProfile profile,
        AMHSPriority priority,
        String subject,
        String channelName,
        String certificateCn,
        String certificateOu,
        Date filingTime,
        String senderOrAddress,
        String recipientOrAddress,
        String presentationAddress,
        Integer ipnRequest,
        String deliveryReport,
        Integer timeoutDr
    ) {
        AMHSMessage message = buildBaseMessage(from, to, body, messageId, profile, priority, subject, channelName, certificateCn, certificateOu, filingTime);
        message.setSenderOrAddress(normalize(senderOrAddress));
        message.setRecipientOrAddress(normalize(recipientOrAddress));
        message.setPresentationAddress(normalize(presentationAddress));
        message.setIpnRequest(ipnRequest);
        message.setDeliveryReport(normalize(deliveryReport));
        message.setTimeoutDr(timeoutDr);

        if (!databaseEnabled) {
            logReceivedMessage(message);
            return message;
        }

        complianceValidator.validate(from, to, body, profile);
        AMHSChannel channel = channelService.requireEnabledChannel(channelName);
        complianceValidator.validateCertificateIdentity(channel, certificateCn, certificateOu);
        message.setChannelName(channel.getName());
        return amhsMessagesRepository.save(message);
    }

    public List<AMHSMessage> findAll() {
        return amhsMessagesRepository.findAll();
    }

    public List<AMHSMessage> findByFilters(String channelName, AMHSProfile profile) {
        if (StringUtils.hasText(channelName) && profile != null) {
            return amhsMessagesRepository.findByChannelNameIgnoreCaseAndProfile(channelName.trim(), profile);
        }
        if (StringUtils.hasText(channelName)) {
            return amhsMessagesRepository.findByChannelNameIgnoreCase(channelName.trim());
        }
        if (profile != null) {
            return amhsMessagesRepository.findByProfile(profile);
        }
        return amhsMessagesRepository.findAll();
    }

    private AMHSMessage buildBaseMessage(
        String from,
        String to,
        String body,
        String messageId,
        AMHSProfile profile,
        AMHSPriority priority,
        String subject,
        String channelName,
        String certificateCn,
        String certificateOu,
        Date filingTime
    ) {
        AMHSMessage message = new AMHSMessage();
        message.setMessageId(resolveMessageId(messageId));
        message.setSender(normalizeUpper(from));
        message.setRecipient(normalizeUpper(to));
        message.setBody(normalize(body));
        message.setProfile(profile);
        message.setPriority(priority == null ? AMHSPriority.GG : priority);
        message.setSubject(normalize(subject));
        message.setChannelName(normalize(channelName));
        message.setCertificateCn(normalize(certificateCn));
        message.setCertificateOu(normalize(certificateOu));
        message.setFilingTime(filingTime == null ? new Date() : filingTime);
        return message;
    }

    private void logReceivedMessage(AMHSMessage message) {
        logger.info(
            "Database disabled. Received AMHS message [messageId={}, from={}, to={}, channel={}, profile={}, priority={}, subject={}, body={}]",
            message.getMessageId(),
            message.getSender(),
            message.getRecipient(),
            message.getChannelName(),
            message.getProfile(),
            message.getPriority(),
            message.getSubject(),
            message.getBody()
        );
    }

    private String resolveMessageId(String messageId) {
        return StringUtils.hasText(messageId) ? messageId.trim() : UUID.randomUUID().toString();
    }

    private String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
    }

    private String normalizeUpper(String value) {
        String normalized = normalize(value);
        return normalized == null ? null : normalized.toUpperCase();
    }
}
