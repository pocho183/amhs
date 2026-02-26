package it.amhs.api;

import java.util.Date;

import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;

public record MessageResponse(
	String messageId,
	String from,
    String to,
    String body,
    String channel,
    AMHSProfile profile,
    AMHSPriority priority,
    String subject,
    String certificateCn,
    String certificateOu,
    Date receivedAt
) { }
