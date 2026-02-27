package it.amhs.api;

import it.amhs.domain.AMHSPriority;
import jakarta.validation.constraints.NotBlank;

public record X400MessageRequest(
    String messageId,
    @NotBlank String body,
    String p3Subject,
    AMHSPriority priority,
    Integer ipnRequest,
    String deliveryReport,
    Integer timeoutDr,
    @NotBlank String p3ProtocolIndex,
    @NotBlank String p3ProtocolAddress,
    @NotBlank String p3ServerAddress,

    String p3CommonName,
    @NotBlank String p3OrganizationUnit,
    @NotBlank String p3OrganizationName,
    @NotBlank String p3PrivateManagementDomain,
    @NotBlank String p3AdministrationManagementDomain,
    @NotBlank String p3CountryName,

    String p3CommonNameRecipient,
    @NotBlank String p3OrganizationUnitRecipient,
    @NotBlank String p3OrganizationNameRecipient,
    @NotBlank String p3PrivateManagementDomainRecipient,
    @NotBlank String p3AdministrationManagementDomainRecipient,
    @NotBlank String p3CountryNameRecipient,

    String channel,
    String certificateCn,
    String certificateOu
) {
}
