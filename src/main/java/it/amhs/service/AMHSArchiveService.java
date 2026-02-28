package it.amhs.service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import it.amhs.repository.AMHSMessageRepository;

@Service
public class AMHSArchiveService {

    private static final Logger logger = LoggerFactory.getLogger(AMHSArchiveService.class);

    private final AMHSMessageRepository messageRepository;
    private final int retentionDays;

    public AMHSArchiveService(
        AMHSMessageRepository messageRepository,
        @Value("${amhs.archive.retention-days:30}") int retentionDays
    ) {
        this.messageRepository = messageRepository;
        this.retentionDays = retentionDays;
    }

    @Scheduled(cron = "${amhs.archive.cleanup.cron:0 0 3 * * *}")
    public void purgeExpiredMessages() {
        Instant cutoffInstant = Instant.now().minus(retentionDays, ChronoUnit.DAYS);
        long deleted = messageRepository.deleteByReceivedAtBefore(Date.from(cutoffInstant));
        if (deleted > 0) {
            logger.info("AMHS archive cleanup deleted {} messages older than {} days", deleted, retentionDays);
        }
    }
}
