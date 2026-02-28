package it.amhs.domain;

import java.util.Date;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class AMHSMessage {

	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "message_id", nullable = false, unique = true)
    private String messageId;
    @Column(nullable = false)
    private String sender;
    @Column(nullable = false)
    private String recipient;
    @Column(nullable = false)
    private String body;
    @Column(name = "channel_name", nullable = false, length = 64)
    private String channelName;
    @Column(name = "certificate_cn", length = 255)
    private String certificateCn;
    @Column(name = "certificate_ou", length = 255)
    private String certificateOu;
    @Column(name = "sender_or_address", length = 1024)
    private String senderOrAddress;
    @Column(name = "recipient_or_address", length = 1024)
    private String recipientOrAddress;
    @Column(name = "presentation_address", length = 255)
    private String presentationAddress;
    @Column(name = "ipn_request")
    private Integer ipnRequest;
    @Column(name = "delivery_report", length = 64)
    private String deliveryReport;
    @Column(name = "timeout_dr")
    private Integer timeoutDr;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AMHSProfile profile;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AMHSPriority priority;
	@Column(name = "subject", length = 255)
	private String subject;
    @Column(name = "filing_time", nullable = false, updatable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date filingTime;
    @Column(name = "received_at", updatable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date receivedAt;

    @PrePersist
    protected void onCreate() {
        if (filingTime == null) {
            filingTime = new Date();
        }
        receivedAt = new Date();
    }
}