package it.amhs.service;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class X400AddressBuilder {

    public String buildPresentationAddress(String protocolIndex, String protocolAddress, String serverAddress) {
        return String.format("%s/%s=%s", normalize(protocolIndex), normalize(protocolAddress), normalize(serverAddress));
    }

    public String buildOrAddress(
        String commonName,
        String organizationUnit,
        String organizationName,
        String privateManagementDomain,
        String administrationManagementDomain,
        String countryName
    ) {
        StringBuilder builder = new StringBuilder();
        builder.append("/C=").append(normalize(countryName).toUpperCase());
        builder.append("/ADMD=").append(normalize(administrationManagementDomain).toUpperCase());
        builder.append("/PRMD=").append(normalize(privateManagementDomain).toUpperCase());
        builder.append("/O=").append(normalize(organizationName).toUpperCase());
        builder.append("/OU1=").append(normalize(organizationUnit).toUpperCase());

        if (StringUtils.hasText(commonName) && !"\"\"".equals(commonName.trim())) {
            builder.append("/CN=").append(commonName.trim());
        }

        return builder.toString();
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
