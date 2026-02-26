package it.amhs.api;


import it.amhs.domain.AMHSPriority;
import it.amhs.domain.AMHSProfile;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record MessageRequest(
    String messageId,
    @NotBlank String from,
    @NotBlank String to,
    @NotBlank String body,
    @NotNull AMHSProfile profile,
    @NotNull AMHSPriority priority,
    String subject
) {
}
